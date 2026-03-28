"""
EtherNet/IP (CIP) Protocol Analyzer.
Ports: TCP/44818, UDP/2222
"""
from __future__ import annotations
import struct


CIP_SERVICES = {
    0x01: "GetAttributes",
    0x0E: "GetAttributeSingle",
    0x10: "SetAttributeSingle",
    0x4C: "ReadTag",
    0x4D: "WriteTag",
    0x52: "ReadTagFragmented",
    0x53: "WriteTagFragmented",
    0x54: "GetInstanceAttributeList",
    0x63: "ListIdentity",
    0x64: "ListInterfaces",
    0x65: "RegisterSession",
    0x66: "UnRegisterSession",
    0x6F: "SendRRData",         # Forward Open is inside this
    0x70: "SendUnitData",
}


class ENIPAnalyzer:
    PROTOCOL_NAME = "EtherNet/IP"
    DEFAULT_PORTS = [44818, 2222]

    @classmethod
    def detect(cls, packet) -> bool:
        try:
            from scapy.layers.inet import TCP, UDP
            for layer in (TCP, UDP):
                if packet.haslayer(layer):
                    if packet[layer].sport in cls.DEFAULT_PORTS or packet[layer].dport in cls.DEFAULT_PORTS:
                        return True
        except Exception:
            pass
        return False

    @classmethod
    def dissect(cls, packet) -> dict | None:
        try:
            from scapy.layers.inet import TCP, UDP
            for layer in (TCP, UDP):
                if packet.haslayer(layer):
                    payload = bytes(packet[layer].payload)
                    break
            else:
                return None
            if len(payload) < 4:
                return None
            command = struct.unpack_from("<H", payload, 0)[0]
            length  = struct.unpack_from("<H", payload, 2)[0]
            return {
                "command": command,
                "command_name": CIP_SERVICES.get(command, f"0x{command:02X}"),
                "length": length,
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
                dst_port = 44818
        except Exception:
            return findings

        cmd = dissected.get("command", 0)

        # 1. Any EtherNet/IP = unencrypted
        key_enc = f"ENIP_UNENCRYPTED:{src_ip}:{dst_ip}"
        if key_enc not in seen:
            seen.add(key_enc)
            findings.append({
                "rule_id": "ENIP_UNENCRYPTED",
                "protocol": cls.PROTOCOL_NAME,
                "severity": "HIGH",
                "finding_type": "UNENCRYPTED_PROTOCOL",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "description": "EtherNet/IP (CIP) opera sin cifrado. Comandos CIP (incluyendo escrituras a PLCs) son visibles en red.",
                "iec62443_ref": "SR 4.1",
                "csf_function": "Protect",
                "recommendation": "Aislar el segmento EtherNet/IP con firewall OT. Considerar CIP Security (DTLS) si los dispositivos lo soportan.",
            })

        # 2. List Identity (device enumeration)
        if cmd == 0x63:
            key_id = f"ENIP_IDENTITY:{src_ip}"
            if key_id not in seen:
                seen.add(key_id)
                findings.append({
                    "rule_id": "ENIP_IDENTITY_REQUEST",
                    "protocol": cls.PROTOCOL_NAME,
                    "severity": "MEDIUM",
                    "finding_type": "DEVICE_ENUMERATION",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "description": "Solicitud List Identity EtherNet/IP detectada. Enumera dispositivos Allen-Bradley/Rockwell sin autenticación.",
                    "iec62443_ref": "SR 1.1",
                    "csf_function": "Identify",
                    "recommendation": "Filtrar solicitudes List Identity (0x63) en el firewall OT para reducir superficie de reconocimiento.",
                })

        # 3. Forward Open (new CIP connection to PLC)
        if cmd == 0x6F:
            key_fo = f"ENIP_FORWARD_OPEN:{src_ip}:{dst_ip}"
            if key_fo not in seen:
                seen.add(key_fo)
                findings.append({
                    "rule_id": "ENIP_FORWARD_OPEN",
                    "protocol": cls.PROTOCOL_NAME,
                    "severity": "HIGH",
                    "finding_type": "UNAUTHORIZED_CONNECTION",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "description": "Solicitud SendRRData/Forward Open detectada. Establece sesión CIP directa con PLC.",
                    "iec62443_ref": "SR 2.1",
                    "csf_function": "Detect",
                    "recommendation": "Verificar que solo dispositivos HMI/SCADA autorizados inicien conexiones CIP. Aplicar ACL en switches industriales.",
                })

        return findings
