"""
IEC 60870-5-104 Protocol Analyzer (SCADA for electric substations).
Port: TCP/2404
"""
from __future__ import annotations
import struct


# ASDU type IDs for control commands (writable operations)
CONTROL_ASDU_TYPES = set(range(45, 70))  # Single cmd, double cmd, setpoint, etc.
MONITORING_ASDU_TYPES = set(range(1, 44))


class IEC104Analyzer:
    PROTOCOL_NAME = "IEC 60870-5-104"
    DEFAULT_PORTS = [2404]

    @classmethod
    def detect(cls, packet) -> bool:
        try:
            from scapy.layers.inet import TCP
            if packet.haslayer(TCP):
                if packet[TCP].sport in cls.DEFAULT_PORTS or packet[TCP].dport in cls.DEFAULT_PORTS:
                    return True
        except Exception:
            pass
        return False

    @classmethod
    def dissect(cls, packet) -> dict | None:
        try:
            from scapy.layers.inet import TCP
            payload = bytes(packet[TCP].payload)
            # IEC 104 APCI: start byte 0x68 + length + 4 control fields
            if len(payload) < 6 or payload[0] != 0x68:
                return None
            apci_length = payload[1]
            frame_type = payload[2] & 0x03
            frame_names = {0: "I-Frame", 1: "S-Frame", 3: "U-Frame"}
            result = {
                "apci_length": apci_length,
                "frame_type": frame_names.get(frame_type, "Unknown"),
                "asdu_type": None,
                "is_control_command": False,
            }
            # I-Frame carries ASDU
            if frame_type == 0 and apci_length >= 10 and len(payload) >= 10:
                asdu_type = payload[6]
                result["asdu_type"] = asdu_type
                result["is_control_command"] = asdu_type in CONTROL_ASDU_TYPES
            return result
        except Exception:
            return None

    @classmethod
    def check_vulnerabilities(cls, packet, dissected: dict, seen: set) -> list[dict]:
        findings = []
        try:
            from scapy.layers.inet import IP, TCP
            src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
            dst_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"
            dst_port = packet[TCP].dport if packet.haslayer(TCP) else 2404
        except Exception:
            return findings

        # 1. Any IEC 104 = unencrypted
        key_enc = f"IEC104_UNENCRYPTED:{src_ip}:{dst_ip}"
        if key_enc not in seen:
            seen.add(key_enc)
            findings.append({
                "rule_id": "IEC104_UNENCRYPTED",
                "protocol": cls.PROTOCOL_NAME,
                "severity": "HIGH",
                "finding_type": "UNENCRYPTED_PROTOCOL",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "description": "IEC 60870-5-104 (SCADA eléctrico) opera sin cifrado. Comandos a subestaciones son visibles en texto plano.",
                "iec62443_ref": "SR 4.1",
                "csf_function": "Protect",
                "recommendation": "Implementar IEC 62351 (TLS) sobre IEC 104. Requiere soporte en RTUs/IEDs de subestación.",
            })

        # 2. Control command (ASDU 45-69)
        if dissected.get("is_control_command"):
            asdu = dissected.get("asdu_type", "?")
            key_ctrl = f"IEC104_CONTROL:{src_ip}:{dst_ip}"
            if key_ctrl not in seen:
                seen.add(key_ctrl)
                findings.append({
                    "rule_id": "IEC104_CONTROL_COMMAND",
                    "protocol": cls.PROTOCOL_NAME,
                    "severity": "CRITICAL",
                    "finding_type": "CONTROL_COMMAND",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "description": f"Comando de control IEC 104 (ASDU tipo {asdu}) detectado sin autenticación. Puede controlar interruptores de subestación.",
                    "iec62443_ref": "SR 2.1",
                    "csf_function": "Protect",
                    "recommendation": "Implementar IEC 62351-5 para autenticación de comandos. Auditar origen de todos los comandos de control.",
                })

        return findings
