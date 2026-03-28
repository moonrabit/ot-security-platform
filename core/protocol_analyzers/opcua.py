"""
OPC-UA Protocol Analyzer.
Port: TCP/4840
"""
from __future__ import annotations
import struct


# OPC-UA Security Modes (from OPC UA Part 4)
SECURITY_MODES = {0: "None", 1: "Sign", 2: "SignAndEncrypt"}

# OPC-UA message types
MSG_TYPES = {
    b"HEL": "Hello",
    b"ACK": "Acknowledge",
    b"ERR": "Error",
    b"MSG": "Message",
    b"OPN": "OpenSecureChannel",
    b"CLO": "CloseSecureChannel",
}


class OPCUAAnalyzer:
    PROTOCOL_NAME = "OPC-UA"
    DEFAULT_PORTS = [4840]

    @classmethod
    def detect(cls, packet) -> bool:
        try:
            from scapy.layers.inet import TCP
            if packet.haslayer(TCP):
                if packet[TCP].sport in cls.DEFAULT_PORTS or packet[TCP].dport in cls.DEFAULT_PORTS:
                    return True
                # Signature: first 3 bytes are a known OPC-UA message type
                payload = bytes(packet[TCP].payload)
                if len(payload) >= 3 and payload[:3] in MSG_TYPES:
                    return True
        except Exception:
            pass
        return False

    @classmethod
    def dissect(cls, packet) -> dict | None:
        try:
            from scapy.layers.inet import TCP
            payload = bytes(packet[TCP].payload)
            if len(payload) < 8:
                return None
            msg_type = payload[:3]
            chunk_type = chr(payload[3])
            if len(payload) < 8:
                return None
            msg_size = struct.unpack_from("<I", payload, 4)[0]
            info = {
                "msg_type": MSG_TYPES.get(msg_type, "Unknown"),
                "chunk_type": chunk_type,
                "msg_size": msg_size,
                "security_mode": None,
            }
            # OpenSecureChannel request contains the security mode
            if msg_type == b"OPN" and len(payload) > 40:
                # SecurityMode is buried in the request body; approximate detection
                # by searching for known security mode bytes in the first 100 bytes
                for i in range(8, min(len(payload)-4, 100)):
                    val = struct.unpack_from("<I", payload, i)[0]
                    if val in (0, 1, 2):
                        info["security_mode"] = val
                        break
            return info
        except Exception:
            return None

    @classmethod
    def check_vulnerabilities(cls, packet, dissected: dict, seen: set) -> list[dict]:
        findings = []
        try:
            from scapy.layers.inet import IP, TCP
            src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
            dst_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"
            dst_port = packet[TCP].dport if packet.haslayer(TCP) else 4840
        except Exception:
            return findings

        security_mode = dissected.get("security_mode")
        msg_type = dissected.get("msg_type", "")

        # 1. OpenSecureChannel with SecurityMode=None
        if msg_type == "OpenSecureChannel" and security_mode == 0:
            key = f"OPCUA_NONE:{src_ip}:{dst_ip}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "rule_id": "OPCUA_NONE_SECURITY",
                    "protocol": cls.PROTOCOL_NAME,
                    "severity": "CRITICAL",
                    "finding_type": "NO_ENCRYPTION",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "description": "Conexión OPC-UA con SecurityMode=None. Sin cifrado ni firma. Todos los datos de proceso son visibles en texto plano.",
                    "iec62443_ref": "SR 4.1",
                    "csf_function": "Protect",
                    "recommendation": "Configurar SecurityMode=SignAndEncrypt con SecurityPolicy=Basic256Sha256 en cliente y servidor OPC-UA.",
                })

        # 2. OpenSecureChannel with SecurityMode=Sign only
        elif msg_type == "OpenSecureChannel" and security_mode == 1:
            key = f"OPCUA_SIGN:{src_ip}:{dst_ip}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "rule_id": "OPCUA_SIGN_ONLY",
                    "protocol": cls.PROTOCOL_NAME,
                    "severity": "MEDIUM",
                    "finding_type": "PARTIAL_SECURITY",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "description": "Conexión OPC-UA con SecurityMode=Sign únicamente. Los datos no están cifrados.",
                    "iec62443_ref": "SR 4.1",
                    "csf_function": "Protect",
                    "recommendation": "Actualizar a SecurityMode=SignAndEncrypt para proteger también la confidencialidad.",
                })

        # 3. Any OPC-UA traffic on default port (potential unencrypted)
        if msg_type not in ("", None) and security_mode is None:
            key = f"OPCUA_TRAFFIC:{src_ip}:{dst_ip}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "rule_id": "OPCUA_UNENCRYPTED",
                    "protocol": cls.PROTOCOL_NAME,
                    "severity": "HIGH",
                    "finding_type": "UNENCRYPTED_PROTOCOL",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "description": "Tráfico OPC-UA detectado. Verificar configuración de seguridad del canal.",
                    "iec62443_ref": "SR 4.1",
                    "csf_function": "Protect",
                    "recommendation": "Auditar la configuración de seguridad de todos los endpoints OPC-UA.",
                })

        return findings
