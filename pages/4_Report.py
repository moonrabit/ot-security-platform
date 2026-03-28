"""
Módulo 4: Generación de Informe PDF.
Exporta el informe completo de evaluación de seguridad OT.
"""
import streamlit as st
from datetime import datetime

from db.database import (
    init_db, get_session, get_zones, get_conduits, get_responses,
    get_scan_sessions, get_findings, get_devices, get_roadmap_items,
)
from core.questionnaire_engine import score_responses, compute_gaps
from core.roadmap_engine import compute_csf_coverage

init_db()

st.set_page_config(page_title="Informe PDF", page_icon="📄", layout="wide")
st.title("📄 Módulo 4: Informe de Evaluación")

if not st.session_state.get("session_id"):
    st.warning("Selecciona o crea una sesión desde la página principal.")
    st.stop()

session_id = st.session_state.session_id
session = get_session(session_id)
if not session:
    st.error("Sesión no encontrada.")
    st.stop()

global_sl_target = st.session_state.get("global_sl_target", 2)

# Load all data
zones = get_zones(session_id)
conduits = get_conduits(session_id)
responses = get_responses(session_id)
scan_sessions = get_scan_sessions(session_id)
all_findings = []
all_devices = []
for ss in scan_sessions:
    all_findings.extend(get_findings(ss["scan_id"]))
    all_devices.extend(get_devices(ss["scan_id"]))
roadmap_items = get_roadmap_items(session_id)

# Compute scores
fr_scores, fr_achieved_sl, overall_sl, overall_pct = {}, {}, 0, 0.0
questionnaire_gaps = []
if responses:
    scores = score_responses(responses)
    fr_scores = scores["fr_scores"]
    fr_achieved_sl = scores["fr_achieved_sl"]
    overall_sl = scores["overall_sl"]
    overall_pct = scores["overall_pct"]
    questionnaire_gaps = compute_gaps(responses, zones, global_sl_target)

csf_coverage = compute_csf_coverage(roadmap_items) if roadmap_items else {}

# ─── Report preview ────────────────────────────────────────────────────────────
st.subheader("Vista previa del informe")

col_info, col_stats = st.columns([2, 1])
with col_info:
    st.markdown(f"""
    | Campo | Valor |
    |-------|-------|
    | Organización | **{session.get('org_name', 'N/A')}** |
    | Sitio | **{session.get('site_name', 'N/A')}** |
    | Fecha | **{datetime.utcnow().strftime('%d/%m/%Y')}** |
    | SL Objetivo | **SL {global_sl_target}** |
    | SL Alcanzado | **SL {overall_sl}** |
    | Score global | **{overall_pct*100:.1f}%** |
    """)

with col_stats:
    st.metric("Preguntas respondidas", len(responses))
    st.metric("Hallazgos de red", len(all_findings))
    st.metric("Ítems de roadmap", len(roadmap_items))
    critical_count = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
    st.metric("Hallazgos críticos", critical_count)

# ─── Report sections selector ─────────────────────────────────────────────────
st.divider()
st.subheader("Secciones a incluir en el informe")
col1, col2 = st.columns(2)
with col1:
    inc_executive = st.checkbox("Resumen ejecutivo", value=True)
    inc_assessment = st.checkbox("Resultados del assessment IEC 62443", value=True)
    inc_scanner = st.checkbox("Hallazgos del escáner de red", value=bool(all_findings))
with col2:
    inc_roadmap = st.checkbox("Roadmap de mejora", value=bool(roadmap_items))
    inc_appendix = st.checkbox("Apéndice metodológico", value=True)

# ─── Check prerequisites ──────────────────────────────────────────────────────
if not responses and not all_findings:
    st.warning("El informe estará vacío si no completás el cuestionario o realizás un escaneo primero.")

# ─── Generate PDF ─────────────────────────────────────────────────────────────
st.divider()

try:
    from reportlab.platypus import SimpleDocTemplate
    reportlab_available = True
except ImportError:
    reportlab_available = False

if not reportlab_available:
    st.error("ReportLab no está instalado. Ejecutá: `pip install reportlab`")
else:
    if st.button("📥 Generar informe PDF", type="primary"):
        with st.spinner("Generando informe PDF..."):
            try:
                from core.report_generator import generate_pdf_report
                pdf_bytes = generate_pdf_report(
                    session=session,
                    zones=zones,
                    conduits=conduits,
                    responses=responses,
                    fr_scores=fr_scores,
                    fr_achieved_sl=fr_achieved_sl,
                    overall_sl=overall_sl,
                    overall_pct=overall_pct,
                    questionnaire_gaps=questionnaire_gaps,
                    scan_sessions=scan_sessions,
                    findings=all_findings,
                    devices=all_devices,
                    roadmap_items=roadmap_items,
                    csf_coverage=csf_coverage,
                    global_sl_target=global_sl_target,
                )
                org_clean = session.get("org_name", "OT").replace(" ", "_")
                filename = f"OT_Security_Assessment_{org_clean}_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
                st.download_button(
                    label="⬇️ Descargar informe PDF",
                    data=pdf_bytes,
                    file_name=filename,
                    mime="application/pdf",
                    type="primary",
                )
                st.success(f"✅ Informe generado: **{filename}**")
            except Exception as e:
                st.error(f"Error al generar el informe: {e}")

# ─── Also offer CSV exports ────────────────────────────────────────────────────
st.divider()
st.subheader("Exportar datos individuales")

import pandas as pd

col_csv1, col_csv2, col_csv3 = st.columns(3)

with col_csv1:
    if roadmap_items:
        rm_df = pd.DataFrame([{
            "Fase": i["phase"], "Prioridad": round(i["priority_score"]),
            "Título": i["title"], "Esfuerzo_días": i["effort_days"],
            "Estado": i["status"],
            "CSF": ", ".join(i.get("csf_functions", [])),
            "NIST": ", ".join(i.get("nist_controls", [])),
        } for i in roadmap_items])
        st.download_button(
            "⬇️ Roadmap (CSV)",
            rm_df.to_csv(index=False).encode("utf-8"),
            file_name=f"roadmap_{session_id[:8]}.csv",
            mime="text/csv",
        )

with col_csv2:
    if all_findings:
        fin_df = pd.DataFrame([{
            "Severidad": f["severity"], "Protocolo": f["protocol"],
            "Tipo": f["finding_type"], "Origen": f["src_ip"],
            "Destino": f["dst_ip"], "Puerto": f["dst_port"],
            "Descripción": f["description"][:100],
            "IEC62443": f["iec62443_ref"],
            "Recomendación": f["recommendation"][:100],
        } for f in all_findings])
        st.download_button(
            "⬇️ Hallazgos de red (CSV)",
            fin_df.to_csv(index=False).encode("utf-8"),
            file_name=f"findings_{session_id[:8]}.csv",
            mime="text/csv",
        )

with col_csv3:
    if responses:
        resp_df = pd.DataFrame([{
            "Pregunta": r["question_id"], "FR": r["fr_number"],
            "Respuesta": r["answer"], "Evidencia": r.get("evidence_note", ""),
            "Zona": r.get("zone_id", "Global"),
        } for r in responses])
        st.download_button(
            "⬇️ Respuestas cuestionario (CSV)",
            resp_df.to_csv(index=False).encode("utf-8"),
            file_name=f"assessment_{session_id[:8]}.csv",
            mime="text/csv",
        )
