"""
Generic analyzer for well-known insecure protocols in OT networks.
Detects Telnet, FTP, HTTP management interfaces, and S7comm.
"""
from __future__ import annotations


class GenericInsecureAnalyzer:
    PROTOCOL_NAME = "Generic"
    DEFAULT_PORTS = [21, 23, 80, 102]

    @classmethod
    def detect(cls, packet) -> bool:
        try:
            from scapy.layers.inet import TCP
            if packet.haslayer(TCP):
                port = packet[TCP].dport
                return port in cls.DEFAULT_PORTS
        except Exception:
            pass
        return False

    @classmethod
    def dissect(cls, packet) -> dict | None:
        try:
            from scapy.layers.inet import TCP
            dport = packet[TCP].dport
            port_map = {21: "FTP", 23: "Telnet", 80: "HTTP", 102: "S7comm"}
            return {"detected_protocol": port_map.get(dport, "Unknown"), "port": dport}
        except Exception:
            return None

    @classmethod
    def check_vulnerabilities(cls, packet, dissected: dict, seen: set) -> list[dict]:
        findings = []
        try:
            from scapy.layers.inet import IP, TCP
            src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
            dst_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"
            dst_port = packet[TCP].dport if packet.haslayer(TCP) else 0
        except Exception:
            return findings

        proto = dissected.get("detected_protocol", "")

        if proto == "Telnet":
            key = f"TELNET:{dst_ip}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "rule_id": "TELNET_DETECTED",
                    "protocol": "Telnet",
                    "severity": "CRITICAL",
                    "finding_type": "INSECURE_PROTOCOL",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "description": "Protocolo Telnet activo en red OT. Transmite credenciales y comandos en texto plano.",
                    "iec62443_ref": "SR 4.1",
                    "csf_function": "Protect",
                    "recommendation": "Deshabilitar Telnet inmediatamente. Usar SSH. Cambiar contraseñas de todos los dispositivos afectados.",
                })

        elif proto == "FTP":
            key = f"FTP:{dst_ip}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "rule_id": "FTP_DETECTED",
                    "protocol": "FTP",
                    "severity": "HIGH",
                    "finding_type": "INSECURE_PROTOCOL",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "description": "FTP activo en red OT. Credenciales y archivos de configuración/firmware transmitidos en texto plano.",
                    "iec62443_ref": "SR 4.1",
                    "csf_function": "Protect",
                    "recommendation": "Reemplazar FTP con SFTP o SCP para transferencia de archivos en OT.",
                })

        elif proto == "HTTP":
            key = f"HTTP:{dst_ip}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "rule_id": "HTTP_MANAGEMENT",
                    "protocol": "HTTP",
                    "severity": "HIGH",
                    "finding_type": "INSECURE_PROTOCOL",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "description": "Interfaz HTTP (sin TLS) activa en red OT. Credenciales de gestión de HMI/switch transmitidas en texto plano.",
                    "iec62443_ref": "SR 4.1",
                    "csf_function": "Protect",
                    "recommendation": "Habilitar HTTPS en todas las interfaces web de gestión. Deshabilitar HTTP.",
                })

        elif proto == "S7comm":
            key = f"S7COMM:{src_ip}:{dst_ip}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "rule_id": "S7COMM_UNENCRYPTED",
                    "protocol": "S7comm (Siemens)",
                    "severity": "HIGH",
                    "finding_type": "UNENCRYPTED_PROTOCOL",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "description": "Protocolo S7comm de Siemens detectado. Permite lectura/escritura de bloques de datos en PLCs S7 sin autenticación.",
                    "iec62443_ref": "SR 4.1",
                    "csf_function": "Protect",
                    "recommendation": "Migrar a S7comm+ con TLS (S7-1200/1500). Aplicar niveles de protección en TIA Portal. Aislar segmento Siemens.",
                })

        return findings
