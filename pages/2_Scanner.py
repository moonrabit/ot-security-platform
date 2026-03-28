"""
Módulo 2: Escáner Pasivo de Protocolos Industriales.
Analiza capturas PCAP o tráfico en vivo para detectar vulnerabilidades en protocolos OT.
"""
import streamlit as st
import tempfile
import os
from pathlib import Path

from db.database import (
    init_db, create_scan_session, insert_finding, insert_device,
    get_scan_sessions, get_findings, get_devices,
)
from visualizations.purdue_diagram import build_purdue_diagram
from visualizations.roadmap_gantt import build_findings_severity_chart

init_db()

st.set_page_config(page_title="Escáner OT", page_icon="🔍", layout="wide")
st.title("🔍 Módulo 2: Escáner Pasivo de Protocolos OT")

if not st.session_state.get("session_id"):
    st.warning("Selecciona o crea una sesión desde la página principal.")
    st.stop()

session_id = st.session_state.session_id

# ─── Check Scapy availability ──────────────────────────────────────────────────
scapy_available = False
try:
    import scapy
    scapy_available = True
except ImportError:
    pass

if not scapy_available:
    st.warning(
        "⚠️ **Scapy no está instalado.** Para habilitar el escáner, ejecutá: `pip install scapy`\n\n"
        "Mientras tanto, podés ver los resultados de escaneos previos si los hay."
    )

st.divider()

tab_scan, tab_results = st.tabs(["🔬 Nuevo Escaneo", "📊 Resultados"])

# ════════════════════════════════════════════════════════════════════════
# TAB 1: NEW SCAN
# ════════════════════════════════════════════════════════════════════════
with tab_scan:
    scan_mode = st.radio(
        "Modo de captura",
        options=["📁 Archivo PCAP", "🔴 Captura en vivo"],
        horizontal=True,
    )

    if scan_mode == "📁 Archivo PCAP":
        st.markdown("**Cargar archivo PCAP para análisis pasivo**")
        uploaded_file = st.file_uploader(
            "Seleccioná un archivo de captura de red (.pcap o .pcapng)",
            type=["pcap", "pcapng", "cap"],
            help="Máximo 500 MB. El archivo no se almacena permanentemente.",
        )

        if uploaded_file and scapy_available:
            if st.button("▶ Iniciar análisis", type="primary"):
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
                    tmp.write(uploaded_file.read())
                    tmp_path = tmp.name

                progress_bar = st.progress(0, text="Iniciando análisis...")
                status_text = st.empty()

                def update_progress(current, total):
                    pct = int(current / max(total, 1) * 100)
                    progress_bar.progress(pct / 100, text=f"Analizando paquetes: {current:,}/{total:,}")

                try:
                    from core.scanner_engine import scan_pcap
                    with st.spinner("Procesando captura..."):
                        result = scan_pcap(tmp_path, session_id, progress_callback=update_progress)

                    progress_bar.progress(1.0, text="✅ Análisis completado")

                    # Save to DB
                    create_scan_session({
                        "scan_id":        result["scan_id"],
                        "session_id":     result["session_id"],
                        "source_type":    "pcap",
                        "source_name":    uploaded_file.name,
                        "total_packets":  result["total_packets"],
                        "ot_packets":     result["ot_packets"],
                        "protocol_stats": result["protocol_stats"],
                        "scanned_at":     result["scanned_at"],
                    })
                    for dev in result["devices"]:
                        insert_device(dev)
                    for finding in result["findings"]:
                        insert_finding(finding)

                    st.session_state["last_scan_id"] = result["scan_id"]
                    st.success(f"✅ Análisis completado: {result['total_packets']:,} paquetes, "
                               f"{result['ot_packets']:,} paquetes OT, "
                               f"{len(result['findings'])} hallazgos.")
                    st.rerun()

                except Exception as e:
                    st.error(f"Error durante el análisis: {e}")
                finally:
                    try:
                        os.unlink(tmp_path)
                    except Exception:
                        pass

        elif uploaded_file and not scapy_available:
            st.error("Scapy es necesario para analizar archivos PCAP. Instalalo con: `pip install scapy`")

    else:  # Live capture
        st.markdown("**Captura en vivo desde interfaz de red**")
        st.warning("⚠️ La captura en vivo requiere privilegios **root/admin**.")

        if scapy_available:
            from core.scanner_engine import get_available_interfaces
            interfaces = get_available_interfaces()
        else:
            interfaces = []

        if interfaces:
            selected_iface = st.selectbox("Interfaz de red", options=interfaces)
            duration = st.slider("Duración de captura (segundos)", min_value=10, max_value=300, value=60)

            if st.button("▶ Iniciar captura", type="primary"):
                try:
                    from core.scanner_engine import scan_live
                    progress_placeholder = st.empty()
                    with st.spinner(f"Capturando en {selected_iface} por {duration} segundos..."):
                        result = scan_live(selected_iface, session_id, duration_seconds=duration)

                    create_scan_session({
                        "scan_id": result["scan_id"], "session_id": result["session_id"],
                        "source_type": "live", "source_name": selected_iface,
                        "total_packets": result["total_packets"], "ot_packets": result["ot_packets"],
                        "protocol_stats": result["protocol_stats"], "scanned_at": result["scanned_at"],
                    })
                    for dev in result["devices"]:
                        insert_device(dev)
                    for finding in result["findings"]:
                        insert_finding(finding)

                    st.session_state["last_scan_id"] = result["scan_id"]
                    st.success(f"Captura completada: {result['total_packets']:,} paquetes, {len(result['findings'])} hallazgos.")
                    st.rerun()

                except PermissionError:
                    st.error("Permiso denegado. Ejecutá la aplicación con sudo para captura en vivo.")
                except Exception as e:
                    st.error(f"Error: {e}")
        else:
            st.info("No se encontraron interfaces de red disponibles, o Scapy no está instalado.")

    # Demo/test option
    with st.expander("🧪 Generar datos de demostración"):
        st.caption("Crea un escaneo simulado con hallazgos de ejemplo para probar la plataforma.")
        if st.button("Generar demo", key="demo_scan"):
            import uuid
            from datetime import datetime
            scan_id = str(uuid.uuid4())
            demo_findings = [
                {"finding_id": str(uuid.uuid4()), "scan_id": scan_id, "protocol": "Modbus/TCP",
                 "severity": "HIGH", "finding_type": "UNENCRYPTED_PROTOCOL",
                 "src_ip": "192.168.1.10", "dst_ip": "192.168.1.100", "dst_port": 502,
                 "description": "Modbus/TCP sin cifrado ni autenticación detectado.",
                 "iec62443_ref": "SR 4.1", "csf_function": "Protect",
                 "recommendation": "Implementar túnel TLS sobre Modbus/TCP."},
                {"finding_id": str(uuid.uuid4()), "scan_id": scan_id, "protocol": "Telnet",
                 "severity": "CRITICAL", "finding_type": "INSECURE_PROTOCOL",
                 "src_ip": "192.168.1.20", "dst_ip": "192.168.1.50", "dst_port": 23,
                 "description": "Telnet activo en HMI. Credenciales en texto plano.",
                 "iec62443_ref": "SR 4.1", "csf_function": "Protect",
                 "recommendation": "Deshabilitar Telnet. Usar SSH."},
                {"finding_id": str(uuid.uuid4()), "scan_id": scan_id, "protocol": "OPC-UA",
                 "severity": "CRITICAL", "finding_type": "NO_ENCRYPTION",
                 "src_ip": "192.168.1.30", "dst_ip": "192.168.1.200", "dst_port": 4840,
                 "description": "OPC-UA SecurityMode=None. Datos de proceso sin cifrar.",
                 "iec62443_ref": "SR 4.1", "csf_function": "Protect",
                 "recommendation": "Configurar SecurityMode=SignAndEncrypt."},
                {"finding_id": str(uuid.uuid4()), "scan_id": scan_id, "protocol": "EtherNet/IP",
                 "severity": "HIGH", "finding_type": "DEVICE_ENUMERATION",
                 "src_ip": "192.168.1.20", "dst_ip": "192.168.1.101", "dst_port": 44818,
                 "description": "List Identity EtherNet/IP detectado. Enumeración de PLCs.",
                 "iec62443_ref": "SR 1.1", "csf_function": "Identify",
                 "recommendation": "Filtrar List Identity en firewall OT."},
                {"finding_id": str(uuid.uuid4()), "scan_id": scan_id, "protocol": "DNP3",
                 "severity": "HIGH", "finding_type": "NO_AUTHENTICATION",
                 "src_ip": "192.168.2.10", "dst_ip": "192.168.2.100", "dst_port": 20000,
                 "description": "DNP3 sin Secure Authentication v5.",
                 "iec62443_ref": "SR 1.2", "csf_function": "Protect",
                 "recommendation": "Actualizar a DNP3 SA v5."},
                {"finding_id": str(uuid.uuid4()), "scan_id": scan_id, "protocol": "Mixed",
                 "severity": "HIGH", "finding_type": "NETWORK_SEGMENTATION",
                 "src_ip": "10.0.1.5", "dst_ip": "192.168.1.100", "dst_port": 502,
                 "description": "Comunicación directa IT (10.0.1.x) → OT (192.168.1.x) sin firewall.",
                 "iec62443_ref": "SR 5.1", "csf_function": "Protect",
                 "recommendation": "Implementar firewall IT/OT con DMZ."},
            ]
            demo_devices = [
                {"device_id": str(uuid.uuid4()), "scan_id": scan_id, "ip_address": "192.168.1.10",
                 "mac_address": "", "protocols": ["Modbus/TCP"], "purdue_level": 2, "packet_count": 1523},
                {"device_id": str(uuid.uuid4()), "scan_id": scan_id, "ip_address": "192.168.1.100",
                 "mac_address": "", "protocols": ["Modbus/TCP", "EtherNet/IP"], "purdue_level": 1, "packet_count": 3201},
                {"device_id": str(uuid.uuid4()), "scan_id": scan_id, "ip_address": "192.168.1.20",
                 "mac_address": "", "protocols": ["EtherNet/IP", "Telnet"], "purdue_level": 2, "packet_count": 847},
                {"device_id": str(uuid.uuid4()), "scan_id": scan_id, "ip_address": "192.168.1.200",
                 "mac_address": "", "protocols": ["OPC-UA"], "purdue_level": 3, "packet_count": 412},
                {"device_id": str(uuid.uuid4()), "scan_id": scan_id, "ip_address": "192.168.2.100",
                 "mac_address": "", "protocols": ["DNP3"], "purdue_level": 1, "packet_count": 247},
            ]
            create_scan_session({
                "scan_id": scan_id, "session_id": session_id,
                "source_type": "demo", "source_name": "Demo simulado",
                "total_packets": 12500, "ot_packets": 6230,
                "protocol_stats": {"Modbus/TCP": 4724, "EtherNet/IP": 1058, "OPC-UA": 412, "DNP3": 247},
                "scanned_at": datetime.utcnow().isoformat(),
            })
            for dev in demo_devices:
                insert_device(dev)
            for f in demo_findings:
                insert_finding(f)
            st.session_state["last_scan_id"] = scan_id
            st.success("Demo generado. Pasá a la pestaña Resultados.")
            st.rerun()


# ════════════════════════════════════════════════════════════════════════
# TAB 2: RESULTS
# ════════════════════════════════════════════════════════════════════════
with tab_results:
    scan_sessions = get_scan_sessions(session_id)
    if not scan_sessions:
        st.info("No hay escaneos previos. Realizá un análisis desde la pestaña 'Nuevo Escaneo'.")
        st.stop()

    import pandas as pd

    # Select scan
    scan_options = {s["scan_id"]: f"{s['source_name']} — {s['scanned_at'][:10]} ({s['ot_packets']:,} paquetes OT)"
                   for s in scan_sessions}
    last_scan_id = st.session_state.get("last_scan_id", scan_sessions[0]["scan_id"])
    selected_scan_id = st.selectbox(
        "Escaneo",
        options=list(scan_options.keys()),
        format_func=lambda x: scan_options[x],
        index=list(scan_options.keys()).index(last_scan_id) if last_scan_id in scan_options else 0,
    )

    scan_info = next(s for s in scan_sessions if s["scan_id"] == selected_scan_id)
    findings = get_findings(selected_scan_id)
    devices = get_devices(selected_scan_id)

    # Summary metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total paquetes", f"{scan_info['total_packets']:,}")
    col2.metric("Paquetes OT", f"{scan_info['ot_packets']:,}")
    col3.metric("Dispositivos OT", len(devices))
    col4.metric("Hallazgos", len(findings))
    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    col5.metric("Críticos", critical_count, delta=f"de {len(findings)}")

    st.divider()

    col_proto, col_sev = st.columns([1, 1])

    with col_proto:
        st.markdown("**Protocolos detectados**")
        proto_stats = scan_info.get("protocol_stats", {})
        if proto_stats:
            import plotly.graph_objects as go
            fig_proto = go.Figure(data=[go.Bar(
                x=list(proto_stats.keys()),
                y=list(proto_stats.values()),
                marker_color="#4488FF",
            )])
            fig_proto.update_layout(
                paper_bgcolor="#0E0E0E", plot_bgcolor="#0E0E0E",
                font=dict(color="#EEE"), height=250,
                margin=dict(l=20, r=20, t=20, b=60),
            )
            st.plotly_chart(fig_proto, use_container_width=True)

    with col_sev:
        st.markdown("**Hallazgos por severidad**")
        fig_sev = build_findings_severity_chart(findings)
        st.plotly_chart(fig_sev, use_container_width=True)

    # Purdue diagram
    st.markdown("**Mapa Purdue de dispositivos detectados**")
    fig_purdue = build_purdue_diagram(devices, findings)
    st.plotly_chart(fig_purdue, use_container_width=True)

    # Findings table
    st.markdown(f"**Hallazgos de seguridad ({len(findings)} total)**")
    sev_filter = st.multiselect(
        "Filtrar por severidad",
        options=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=["CRITICAL", "HIGH", "MEDIUM"],
    )
    proto_filter = st.multiselect(
        "Filtrar por protocolo",
        options=list({f.get("protocol", "") for f in findings}),
        default=[],
    )

    filtered = [
        f for f in findings
        if f.get("severity") in sev_filter
        and (not proto_filter or f.get("protocol") in proto_filter)
    ]

    SEV_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}

    for f in sorted(filtered, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x.get("severity","INFO"))):
        emoji = SEV_EMOJI.get(f.get("severity"), "⚪")
        with st.expander(f"{emoji} [{f['severity']}] {f['protocol']} — {f['finding_type']} | {f['src_ip']} → {f['dst_ip']}"):
            st.markdown(f"**Descripción:** {f['description']}")
            st.markdown(f"**IEC 62443:** `{f['iec62443_ref']}` | **NIST CSF:** {f['csf_function']}")
            st.success(f"**Recomendación:** {f['recommendation']}")

    # Device inventory
    st.markdown("**Inventario de dispositivos OT detectados**")
    if devices:
        dev_df = pd.DataFrame([{
            "IP": d["ip_address"],
            "Protocolos": ", ".join(d.get("protocols", [])),
            "Nivel Purdue": f"L{d.get('purdue_level', '?')}",
            "Paquetes": d.get("packet_count", 0),
        } for d in devices])
        st.dataframe(dev_df, use_container_width=True, hide_index=True)
