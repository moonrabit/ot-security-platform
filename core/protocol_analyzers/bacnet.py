"""
BACnet/IP Protocol Analyzer.
Port: UDP/47808 (0xBAC0)
"""
from __future__ import annotations


BACNET_PDU_TYPES = {
    0x00: "ConfirmedRequest",
    0x10: "UnconfirmedRequest",   # Who-Is, I-Am, etc.
    0x20: "SimpleACK",
    0x30: "ComplexACK",
    0x40: "SegmentACK",
    0x50: "Error",
    0x60: "Reject",
    0x70: "Abort",
}

BACNET_UNCONFIRMED_SERVICES = {
    0: "IAm",
    1: "IHave",
    2: "UnconfirmedCOVNotification",
    3: "UnconfirmedEventNotification",
    4: "UnconfirmedPrivateTransfer",
    5: "UnconfirmedTextMessage",
    6: "TimeSynchronization",
    7: "WhoHas",
    8: "WhoIs",
    9: "UTCTimeSynchronization",
}

BACNET_CONFIRMED_SERVICES = {
    15: "ReadProperty",
    16: "ReadPropertyMultiple",
    15: "ReadProperty",
    28: "WriteProperty",
    16: "ReadPropertyMultiple",
}


class BACnetAnalyzer:
    PROTOCOL_NAME = "BACnet"
    DEFAULT_PORTS = [47808]

    @classmethod
    def detect(cls, packet) -> bool:
        try:
            from scapy.layers.inet import UDP
            if packet.haslayer(UDP):
                if packet[UDP].sport in cls.DEFAULT_PORTS or packet[UDP].dport in cls.DEFAULT_PORTS:
                    return True
        except Exception:
            pass
        return False

    @classmethod
    def dissect(cls, packet) -> dict | None:
        try:
            from scapy.layers.inet import UDP
            payload = bytes(packet[UDP].payload)
            # BACnet/IP: 4-byte BVLC header + NPDU + APDU
            if len(payload) < 6:
                return None
            bvlc_type = payload[0]
            if bvlc_type != 0x81:  # BACnet/IP
                return None
            bvlc_function = payload[1]
            # NPDU starts at offset 4
            npdu = payload[4:]
            if len(npdu) < 2:
                return None
            # APDU starts after NPDU
            apdu_offset = 2 + (4 if (npdu[1] & 0x08) else 0) + (4 if (npdu[1] & 0x04) else 0)
            if len(npdu) <= apdu_offset:
                return None
            apdu = npdu[apdu_offset:]
            pdu_type = apdu[0] & 0xF0
            service = apdu[1] if len(apdu) > 1 else None
            return {
                "bvlc_function": bvlc_function,
                "pdu_type": pdu_type,
                "pdu_type_name": BACNET_PDU_TYPES.get(pdu_type, "Unknown"),
                "service_code": service,
                "service_name": (
                    BACNET_UNCONFIRMED_SERVICES.get(service, f"svc_{service}")
                    if pdu_type == 0x10
                    else BACNET_CONFIRMED_SERVICES.get(service, f"svc_{service}")
                ),
            }
        except Exception:
            return None

    @classmethod
    def check_vulnerabilities(cls, packet, dissected: dict, seen: set) -> list[dict]:
        findings = []
        try:
            from scapy.layers.inet import IP, UDP
            src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
            dst_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"
            dst_port = packet[UDP].dport if packet.haslayer(UDP) else 47808
        except Exception:
            return findings

        pdu_type = dissected.get("pdu_type")
        service = dissected.get("service_code")

        # 1. Any BACnet = unencrypted (unless BACnet/SC)
        key_enc = f"BACNET_UNENCRYPTED:{src_ip}:{dst_ip}"
        if key_enc not in seen:
            seen.add(key_enc)
            findings.append({
                "rule_id": "BACNET_UNENCRYPTED",
                "protocol": cls.PROTOCOL_NAME,
                "severity": "HIGH",
                "finding_type": "UNENCRYPTED_PROTOCOL",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "description": "BACnet/IP opera sin cifrado. Comandos de control de edificio (HVAC, iluminación, acceso) visibles en red.",
                "iec62443_ref": "SR 4.1",
                "csf_function": "Protect",
                "recommendation": "Implementar BACnet/SC (Secure Connect) si los dispositivos lo soportan. Aislar con firewall como alternativa.",
            })

        # 2. Who-Is broadcast (device discovery)
        if pdu_type == 0x10 and service == 8:
            key_whois = f"BACNET_WHOIS:{src_ip}"
            if key_whois not in seen:
                seen.add(key_whois)
                findings.append({
                    "rule_id": "BACNET_WHO_IS_BROADCAST",
                    "protocol": cls.PROTOCOL_NAME,
                    "severity": "MEDIUM",
                    "finding_type": "DEVICE_ENUMERATION",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "description": "Broadcast BACnet Who-Is detectado. Permite enumerar todos los dispositivos BACnet sin autenticación.",
                    "iec62443_ref": "SR 1.1",
                    "csf_function": "Identify",
                    "recommendation": "Segmentar dispositivos BACnet en VLANs dedicadas. Filtrar Who-Is entre segmentos con firewall BACnet-aware.",
                })

        # 3. WriteProperty (write to BACnet object)
        if pdu_type == 0x00 and service == 15:
            key_write = f"BACNET_WRITE:{src_ip}:{dst_ip}"
            if key_write not in seen:
                seen.add(key_write)
                findings.append({
                    "rule_id": "BACNET_WRITE_PROPERTY",
                    "protocol": cls.PROTOCOL_NAME,
                    "severity": "HIGH",
                    "finding_type": "WRITE_OPERATION",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "description": "Escritura BACnet WriteProperty detectada. Sin autenticación, puede modificar setpoints de HVAC u otros parámetros.",
                    "iec62443_ref": "SR 2.1",
                    "csf_function": "Detect",
                    "recommendation": "Implementar listas de control de acceso BACnet o migrar a BACnet/SC con autenticación.",
                })

        return findings
