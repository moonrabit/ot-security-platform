"""
DNP3 Protocol Analyzer.
Port: TCP/20000 or UDP/20000
"""
from __future__ import annotations


class DNP3Analyzer:
    PROTOCOL_NAME = "DNP3"
    DEFAULT_PORTS = [20000]

    @classmethod
    def detect(cls, packet) -> bool:
        try:
            from scapy.layers.inet import TCP, UDP
            for layer in (TCP, UDP):
                if packet.haslayer(layer):
                    sport = packet[layer].sport
                    dport = packet[layer].dport
                    if sport in cls.DEFAULT_PORTS or dport in cls.DEFAULT_PORTS:
                        return True
            # Payload signature: DNP3 start bytes 0x0564
            raw = cls._get_raw_payload(packet)
            if raw and len(raw) >= 2 and raw[0] == 0x05 and raw[1] == 0x64:
                return True
        except Exception:
            pass
        return False

    @classmethod
    def dissect(cls, packet) -> dict | None:
        try:
            raw = cls._get_raw_payload(packet)
            if not raw or len(raw) < 10:
                return None
            if raw[0] != 0x05 or raw[1] != 0x64:
                return None
            length = raw[2]
            ctrl = raw[3]
            dst_addr = int.from_bytes(raw[4:6], "little")
            src_addr = int.from_bytes(raw[6:8], "little")
            crc = int.from_bytes(raw[8:10], "little")
            # Check for Secure Authentication: Application Layer Function Code 32
            has_auth = len(raw) > 11 and raw[11] == 0x20
            return {
                "length": length,
                "ctrl": ctrl,
                "dst_addr": dst_addr,
                "src_addr": src_addr,
                "has_auth": has_auth,
            }
        except Exception:
            return None

    @classmethod
    def check_vulnerabilities(cls, packet, dissected: dict, seen: set) -> list[dict]:
        findings = []
        try:
            from scapy.layers.inet import IP, TCP, UDP
            src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
            dst_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"
            for layer in (TCP, UDP):
                if packet.haslayer(layer):
                    dst_port = packet[layer].dport
                    break
            else:
                dst_port = 20000
        except Exception:
            return findings

        # 1. No Secure Authentication
        if not dissected.get("has_auth", False):
            key = f"DNP3_NO_AUTH:{src_ip}:{dst_ip}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "rule_id": "DNP3_NO_AUTH",
                    "protocol": cls.PROTOCOL_NAME,
                    "severity": "HIGH",
                    "finding_type": "NO_AUTHENTICATION",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "description": "Tráfico DNP3 sin Secure Authentication v5. Vulnerable a replay attacks y spoofing de comandos SCADA.",
                    "iec62443_ref": "SR 1.2",
                    "csf_function": "Protect",
                    "recommendation": "Actualizar a DNP3 Secure Authentication v5 (IEEE 1815-2012). Validar soporte con el proveedor de RTUs.",
                })

        return findings

    @classmethod
    def _get_raw_payload(cls, packet) -> bytes | None:
        try:
            from scapy.layers.inet import TCP, UDP
            for layer in (TCP, UDP):
                if packet.haslayer(layer):
                    return bytes(packet[layer].payload)
        except Exception:
            pass
        return None
