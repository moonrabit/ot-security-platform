"""
Passive Industrial Protocol Scanner.
Analyzes PCAP files (or live captures) for OT protocol vulnerabilities.
"""
from __future__ import annotations
import uuid
from datetime import datetime
from pathlib import Path
from typing import Generator
from collections import defaultdict


OT_PORTS = {
    502, 20000, 44818, 2222, 4840, 47808, 2404, 102, 21, 23, 80
}

# Approximate Purdue level mapping based on typical protocol usage
PROTOCOL_PURDUE_MAP = {
    "Modbus/TCP":           1,
    "DNP3":                 1,
    "EtherNet/IP":          1,
    "OPC-UA":               3,
    "BACnet":               1,
    "IEC 60870-5-104":      1,
    "S7comm (Siemens)":     1,
    "Telnet":               2,
    "FTP":                  2,
    "HTTP":                 2,
    "PROFINET":             1,
}


def scan_pcap(
    pcap_path: str | Path,
    session_id: str,
    progress_callback=None,
) -> dict:
    """
    Scan a PCAP file for OT protocol vulnerabilities.

    Returns a result dict with:
        scan_id, session_id, source_name, total_packets, ot_packets,
        protocol_stats, devices, findings, scanned_at
    """
    from core.protocol_analyzers import ALL_ANALYZERS

    scan_id = str(uuid.uuid4())
    scanned_at = datetime.utcnow().isoformat()
    protocol_stats: dict[str, int] = defaultdict(int)
    devices: dict[str, dict] = {}
    seen_findings: set = set()
    raw_findings: list[dict] = []

    total_packets = 0
    ot_packets = 0

    try:
        from scapy.utils import rdpcap
        from scapy.layers.inet import IP
        packets = rdpcap(str(pcap_path))
    except ImportError:
        raise RuntimeError("Scapy no está instalado. Ejecuta: pip install scapy")
    except Exception as e:
        raise RuntimeError(f"No se pudo leer el archivo PCAP: {e}")

    total_packets = len(packets)

    for idx, pkt in enumerate(packets):
        if progress_callback and idx % 1000 == 0:
            progress_callback(idx, total_packets)

        is_ot = False
        for analyzer in ALL_ANALYZERS:
            if analyzer.detect(pkt):
                is_ot = True
                dissected = analyzer.dissect(pkt)
                if dissected is None:
                    dissected = {}
                protocol_stats[analyzer.PROTOCOL_NAME] += 1
                new_findings = analyzer.check_vulnerabilities(pkt, dissected, seen_findings)
                raw_findings.extend(new_findings)

                # Track device
                try:
                    src_ip = pkt[IP].src
                    if src_ip not in devices:
                        devices[src_ip] = {
                            "ip_address": src_ip,
                            "protocols": set(),
                            "packet_count": 0,
                            "purdue_level": PROTOCOL_PURDUE_MAP.get(analyzer.PROTOCOL_NAME, 2),
                        }
                    devices[src_ip]["protocols"].add(analyzer.PROTOCOL_NAME)
                    devices[src_ip]["packet_count"] += 1
                except Exception:
                    pass

        if is_ot:
            ot_packets += 1

    # Detect direct IT/OT communication (heuristic: RFC1918 /24 subnets)
    it_ot_findings = _check_it_ot_separation(packets, seen_findings)
    raw_findings.extend(it_ot_findings)

    # Serialize devices
    device_list = []
    for ip, dev in devices.items():
        device_list.append({
            "device_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "ip_address": ip,
            "mac_address": "",
            "protocols": list(dev["protocols"]),
            "purdue_level": dev["purdue_level"],
            "packet_count": dev["packet_count"],
        })

    # Serialize findings
    finding_list = []
    for f in raw_findings:
        finding_list.append({
            "finding_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            **{k: v for k, v in f.items() if k != "rule_id"},
        })

    return {
        "scan_id": scan_id,
        "session_id": session_id,
        "source_type": "pcap",
        "source_name": Path(pcap_path).name,
        "total_packets": total_packets,
        "ot_packets": ot_packets,
        "protocol_stats": dict(protocol_stats),
        "devices": device_list,
        "findings": finding_list,
        "scanned_at": scanned_at,
    }


def scan_live(
    interface: str,
    session_id: str,
    duration_seconds: int = 60,
    progress_callback=None,
) -> dict:
    """
    Perform live passive capture and analysis on a network interface.
    Requires root/admin privileges.
    """
    import os
    from core.protocol_analyzers import ALL_ANALYZERS

    if os.geteuid() != 0:
        raise PermissionError("Live capture requiere privilegios root/admin.")

    try:
        from scapy.all import sniff
        from scapy.layers.inet import IP
    except ImportError:
        raise RuntimeError("Scapy no está instalado. Ejecuta: pip install scapy")

    scan_id = str(uuid.uuid4())
    scanned_at = datetime.utcnow().isoformat()
    protocol_stats: dict[str, int] = defaultdict(int)
    devices: dict[str, dict] = {}
    seen_findings: set = set()
    raw_findings: list[dict] = []
    total_packets = 0
    ot_packets = 0

    def process_packet(pkt):
        nonlocal total_packets, ot_packets
        total_packets += 1
        is_ot = False
        for analyzer in ALL_ANALYZERS:
            if analyzer.detect(pkt):
                is_ot = True
                dissected = analyzer.dissect(pkt) or {}
                protocol_stats[analyzer.PROTOCOL_NAME] += 1
                new_findings = analyzer.check_vulnerabilities(pkt, dissected, seen_findings)
                raw_findings.extend(new_findings)
                try:
                    src_ip = pkt[IP].src
                    if src_ip not in devices:
                        devices[src_ip] = {
                            "ip_address": src_ip,
                            "protocols": set(),
                            "packet_count": 0,
                            "purdue_level": PROTOCOL_PURDUE_MAP.get(analyzer.PROTOCOL_NAME, 2),
                        }
                    devices[src_ip]["protocols"].add(analyzer.PROTOCOL_NAME)
                    devices[src_ip]["packet_count"] += 1
                except Exception:
                    pass
        if is_ot:
            ot_packets += 1

    sniff(iface=interface, prn=process_packet, timeout=duration_seconds, store=False)

    device_list = [
        {
            "device_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "ip_address": ip,
            "mac_address": "",
            "protocols": list(dev["protocols"]),
            "purdue_level": dev["purdue_level"],
            "packet_count": dev["packet_count"],
        }
        for ip, dev in devices.items()
    ]

    finding_list = [
        {"finding_id": str(uuid.uuid4()), "scan_id": scan_id,
         **{k: v for k, v in f.items() if k != "rule_id"}}
        for f in raw_findings
    ]

    return {
        "scan_id": scan_id,
        "session_id": session_id,
        "source_type": "live",
        "source_name": interface,
        "total_packets": total_packets,
        "ot_packets": ot_packets,
        "protocol_stats": dict(protocol_stats),
        "devices": device_list,
        "findings": finding_list,
        "scanned_at": scanned_at,
    }


def get_available_interfaces() -> list[str]:
    """Return available network interfaces for live capture."""
    try:
        from scapy.arch import get_if_list
        return get_if_list()
    except Exception:
        return []


def _check_it_ot_separation(packets, seen: set) -> list[dict]:
    """
    Heuristic: detect direct communication between typical IT and OT subnets.
    OT subnets often use 192.168.0.x/1.x; IT uses different /16 ranges.
    This is very approximate — real environments vary widely.
    """
    findings = []
    try:
        from scapy.layers.inet import IP, TCP, UDP
        ot_ips: set[str] = set()
        all_comm: list[tuple] = []

        for pkt in packets:
            if pkt.haslayer(IP):
                src = pkt[IP].src
                dst = pkt[IP].dst
                for analyzer_port in OT_PORTS:
                    try:
                        sport = pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport
                        dport = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport
                        if sport == analyzer_port or dport == analyzer_port:
                            ot_ips.add(src)
                            ot_ips.add(dst)
                    except Exception:
                        pass

        # Look for IPs communicating with OT devices from different /16 subnets
        for pkt in packets:
            if pkt.haslayer(IP):
                src = pkt[IP].src
                dst = pkt[IP].dst
                src_net = ".".join(src.split(".")[:2])
                dst_net = ".".join(dst.split(".")[:2])
                if dst in ot_ips and src not in ot_ips and src_net != dst_net:
                    key = f"IT_OT:{src_net}:{dst_net}"
                    if key not in seen:
                        seen.add(key)
                        findings.append({
                            "rule_id": "IT_OT_DIRECT_COMMUNICATION",
                            "protocol": "Mixed",
                            "severity": "HIGH",
                            "finding_type": "NETWORK_SEGMENTATION",
                            "src_ip": src,
                            "dst_ip": dst,
                            "dst_port": 0,
                            "description": f"Comunicación directa detectada entre red IT ({src_net}.x.x) y dispositivo OT ({dst}). Posible ausencia de firewall IT/OT.",
                            "iec62443_ref": "SR 5.1",
                            "csf_function": "Protect",
                            "recommendation": "Implementar firewall entre IT y OT con política de denegación por defecto. Crear DMZ para intercambio de datos.",
                        })
    except Exception:
        pass
    return findings
