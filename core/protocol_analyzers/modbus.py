"""
Modbus/TCP Protocol Analyzer.
Port: TCP/502
"""
from __future__ import annotations
import struct


class ModbusAnalyzer:
    PROTOCOL_NAME = "Modbus/TCP"
    DEFAULT_PORTS = [502]

    # Modbus function codes that perform write operations
    WRITE_FUNCTION_CODES = {5, 6, 15, 16, 22, 23}
    # Diagnostic / device identification
    INFO_FUNCTION_CODES = {8, 43}

    @classmethod
    def detect(cls, packet) -> bool:
        """Detect Modbus/TCP by port."""
        try:
            from scapy.layers.inet import TCP
            if packet.haslayer(TCP):
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                return sport in cls.DEFAULT_PORTS or dport in cls.DEFAULT_PORTS
        except Exception:
            pass
        return False

    @classmethod
    def dissect(cls, packet) -> dict | None:
        """Parse MBAP header + function code from raw payload."""
        try:
            from scapy.layers.inet import TCP
            if not packet.haslayer(TCP):
                return None
            payload = bytes(packet[TCP].payload)
            if len(payload) < 8:
                return None
            transaction_id, protocol_id, length, unit_id, function_code = struct.unpack(">HHHBB", payload[:8])
            if protocol_id != 0:
                return None
            return {
                "transaction_id": transaction_id,
                "unit_id": unit_id,
                "function_code": function_code,
                "data": payload[8:],
            }
        except Exception:
            return None

    @classmethod
    def check_vulnerabilities(cls, packet, dissected: dict, seen: set) -> list[dict]:
        findings = []
        try:
            from scapy.layers.inet import IP, TCP
            src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
            dst_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"
            dst_port = packet[TCP].dport if packet.haslayer(TCP) else 502
        except Exception:
            return findings

        fc = dissected.get("function_code", 0)

        # 1. Any Modbus packet = unencrypted
        key_enc = f"MODBUS_UNENCRYPTED:{src_ip}:{dst_ip}"
        if key_enc not in seen:
            seen.add(key_enc)
            findings.append({
                "rule_id": "MODBUS_UNENCRYPTED",
                "protocol": cls.PROTOCOL_NAME,
                "severity": "HIGH",
                "finding_type": "UNENCRYPTED_PROTOCOL",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "description": "Modbus/TCP transmite datos en texto plano sin autenticación ni cifrado.",
                "iec62443_ref": "SR 4.1",
                "csf_function": "Protect",
                "recommendation": "Implementar túnel TLS sobre Modbus/TCP o aislar el segmento con firewall OT restrictivo.",
            })

        # 2. Write to broadcast IP
        if fc in cls.WRITE_FUNCTION_CODES and (dst_ip.endswith(".255") or dst_ip == "255.255.255.255"):
            key_bcast = f"MODBUS_BROADCAST_WRITE:{src_ip}"
            if key_bcast not in seen:
                seen.add(key_bcast)
                findings.append({
                    "rule_id": "MODBUS_BROADCAST_WRITE",
                    "protocol": cls.PROTOCOL_NAME,
                    "severity": "CRITICAL",
                    "finding_type": "BROADCAST_WRITE",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "description": f"Comando de escritura Modbus (FC {fc}) enviado a dirección broadcast. Riesgo de DoS en múltiples PLCs.",
                    "iec62443_ref": "SR 7.1",
                    "csf_function": "Protect",
                    "recommendation": "Bloquear escrituras broadcast en el firewall OT. Auditar el dispositivo origen.",
                })

        # 3. Write operations
        elif fc in cls.WRITE_FUNCTION_CODES:
            key_write = f"MODBUS_WRITE:{src_ip}:{dst_ip}"
            if key_write not in seen:
                seen.add(key_write)
                findings.append({
                    "rule_id": "MODBUS_WRITE_COIL",
                    "protocol": cls.PROTOCOL_NAME,
                    "severity": "HIGH",
                    "finding_type": "WRITE_OPERATION",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "description": f"Operación de escritura Modbus (FC {fc}) detectada. Sin autenticación, cualquier dispositivo puede modificar el proceso.",
                    "iec62443_ref": "SR 2.1",
                    "csf_function": "Detect",
                    "recommendation": "Implementar whitelist de dispositivos autorizados a realizar escrituras Modbus.",
                })

        # 4. Device identification
        elif fc == 43:
            key_id = f"MODBUS_DEVICE_ID:{src_ip}:{dst_ip}"
            if key_id not in seen:
                seen.add(key_id)
                findings.append({
                    "rule_id": "MODBUS_DEVICE_IDENTIFICATION",
                    "protocol": cls.PROTOCOL_NAME,
                    "severity": "MEDIUM",
                    "finding_type": "DEVICE_ENUMERATION",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "description": "Función Read Device Identification (FC 43) detectada. Permite enumerar información del dispositivo.",
                    "iec62443_ref": "SR 1.1",
                    "csf_function": "Identify",
                    "recommendation": "Filtrar FC 43 en el firewall OT si no es requerida operacionalmente.",
                })

        return findings
