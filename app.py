"""
OT Security Assessment Platform
Main entry point for the Streamlit multi-page application.
"""
import streamlit as st
import os
from db.database import init_db

st.set_page_config(
    page_title="OT Security Assessment Platform",
    page_icon="🏭",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Initialize DB on first run
init_db()

# Bootstrap session state
if "session_id" not in st.session_state:
    st.session_state.session_id = None
if "org_name" not in st.session_state:
    st.session_state.org_name = ""

# ─── Landing Page ─────────────────────────────────────────────────────────────
st.title(" OT Security Assessment Platform")
st.markdown(
    """
    Plataforma integral para relevar el estado de seguridad de plantas industriales
    basada en **IEC 62443**, el **Modelo Purdue** y el **NIST CSF**.
    """
)

col1, col2, col3 = st.columns(3)

with col1:
    st.info(
        """
        ### 📋 Módulo 1: Assessment IEC 62443
        Cuestionario estructurado que evalúa los 7 Requisitos Fundamentales (FR1–FR7)
        y calcula el Security Level alcanzado por zona/conduit.
        """
    )

with col2:
    st.info(
        """
        ### 🔍 Módulo 2: Escáner Pasivo de Protocolos
        Análisis de capturas de red (PCAP) para detectar protocolos industriales
        (Modbus, DNP3, EtherNet/IP, OPC-UA, BACnet, IEC 104) e identificar vulnerabilidades.
        """
    )

with col3:
    st.info(
        """
        ### 🗺️ Módulo 3: Roadmap de Mejora
        Gap analysis combinado con generación de plan de mejora priorizado,
        alineado al Modelo Purdue, IEC 62443 y NIST CSF, con export PDF.
        """
    )

st.divider()

# ─── Quick Start / Recent Sessions ────────────────────────────────────────────
from db.database import get_recent_sessions
import pandas as pd

sessions = get_recent_sessions(limit=10)

col_new, col_load = st.columns([1, 2])

with col_new:
    st.subheader("Nueva evaluación")
    org = st.text_input("Organización / Planta", placeholder="ACME Industrial S.A.")
    site = st.text_input("Sitio / Planta específica", placeholder="Planta Norte – Línea 1")
    if st.button("▶ Iniciar evaluación", type="primary", disabled=not org):
        from db.database import create_session
        import uuid
        session_id = str(uuid.uuid4())
        create_session(session_id, org, site)
        st.session_state.session_id = session_id
        st.session_state.org_name = org
        st.success(f"Sesión creada: {session_id[:8]}...")
        st.info("Navega al módulo **Assessment** en el menú lateral.")

with col_load:
    st.subheader("Evaluaciones recientes")
    if sessions:
        df = pd.DataFrame(sessions, columns=["ID", "Organización", "Sitio", "Fecha", "Estado"])
        df["ID_short"] = df["ID"].str[:8]
        st.dataframe(
            df[["ID_short", "Organización", "Sitio", "Fecha", "Estado"]],
            use_container_width=True,
            hide_index=True,
        )
        selected_id = st.selectbox(
            "Cargar sesión",
            options=[""] + [row[0] for row in sessions],
            format_func=lambda x: "Seleccionar..." if x == "" else f"{x[:8]} – {next((r[1] for r in sessions if r[0]==x), '')}",
        )
        if selected_id and st.button("Cargar sesión seleccionada"):
            st.session_state.session_id = selected_id
            st.session_state.org_name = next((r[1] for r in sessions if r[0] == selected_id), "")
            st.success("Sesión cargada. Navega al módulo deseado.")
    else:
        st.caption("No hay evaluaciones previas. Crea una nueva para comenzar.")

# ─── Framework Summary ─────────────────────────────────────────────────────────
st.divider()
st.subheader("Marco de referencia")

tab1, tab2, tab3 = st.tabs(["IEC 62443", "Modelo Purdue", "NIST CSF"])

with tab1:
    st.markdown("""
    | FR | Nombre | Descripción |
    |----|--------|-------------|
    | FR 1 | Identificación y Autenticación (IAC) | Identificar y autenticar todos los usuarios, procesos y dispositivos |
    | FR 2 | Control de Uso (UC) | Hacer cumplir los privilegios asignados a usuarios autenticados |
    | FR 3 | Integridad del Sistema (SI) | Garantizar la integridad del IACS ante manipulaciones no autorizadas |
    | FR 4 | Confidencialidad de Datos (DC) | Proteger la confidencialidad de información en canales de comunicación |
    | FR 5 | Flujo de Datos Restringido (RDF) | Segmentar el IACS en zonas y conductos para limitar flujos innecesarios |
    | FR 6 | Respuesta Oportuna a Eventos (TRE) | Detectar y reportar violaciones de seguridad |
    | FR 7 | Disponibilidad de Recursos (RA) | Garantizar disponibilidad ante degradación o denegación de servicio |
    """)

with tab2:
    st.markdown("""
    | Nivel | Nombre | Ejemplos |
    |-------|--------|---------|
    | 0 | Field Devices | Sensores, actuadores, drives |
    | 1 | Basic Control | PLCs, RTUs, DCS |
    | 2 | Supervisory | HMI, SCADA servers |
    | 3 | Site Operations | Historian, MES, OPC Server |
    | 4 | Business Planning | ERP |
    | 5 | Enterprise | Red corporativa |
    """)

with tab3:
    st.markdown("""
    | Función | Descripción |
    |---------|-------------|
    | **Identify** | Desarrollar comprensión organizacional para gestionar riesgo de ciberseguridad |
    | **Protect** | Implementar salvaguardas para garantizar la entrega de servicios críticos |
    | **Detect** | Implementar actividades para identificar ocurrencia de un evento de ciberseguridad |
    | **Respond** | Tomar acción respecto a un incidente de ciberseguridad detectado |
    | **Recover** | Mantener planes de resiliencia y restaurar capacidades comprometidas |
    """)

st.caption("v1.0 | OT Security Assessment Platform | IEC 62443 · Purdue Model · NIST CSF")
