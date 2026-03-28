"""
Módulo 3: Roadmap de Mejora.
Gap analysis combinado + plan de mejora priorizado alineado a IEC 62443, Purdue y NIST CSF.
"""
import streamlit as st
import pandas as pd

from db.database import (
    init_db, get_responses, get_zones, get_scan_sessions, get_findings,
    get_roadmap_items, upsert_roadmap_item, delete_roadmap_items,
    update_roadmap_status,
)
from core.questionnaire_engine import score_responses, compute_gaps
from core.roadmap_engine import (
    generate_roadmap, compute_csf_coverage, merge_gaps_from_findings,
)
from visualizations.roadmap_gantt import build_gantt_chart, build_csf_donut
from visualizations.radar_chart import build_radar_chart
from config import FOUNDATIONAL_REQUIREMENTS, NIST_CSF_FUNCTIONS

init_db()

st.set_page_config(page_title="Roadmap de Mejora", page_icon="🗺️", layout="wide")
st.title("🗺️ Módulo 3: Roadmap de Mejora OT")

if not st.session_state.get("session_id"):
    st.warning("Selecciona o crea una sesión desde la página principal.")
    st.stop()

session_id = st.session_state.session_id
global_sl_target = st.session_state.get("global_sl_target", 2)

# ─── Load data ────────────────────────────────────────────────────────────────
responses = get_responses(session_id)
zones = get_zones(session_id)
scan_sessions = get_scan_sessions(session_id)
all_findings = []
for ss in scan_sessions:
    all_findings.extend(get_findings(ss["scan_id"]))

has_questionnaire = bool(responses)
has_scanner = bool(all_findings)

if not has_questionnaire and not has_scanner:
    st.info(
        "Para generar el roadmap necesitás:\n"
        "- Completar el **cuestionario IEC 62443** (Módulo 1), o\n"
        "- Realizar un **escaneo de red** (Módulo 2)\n\n"
        "Podés hacerlo desde los módulos correspondientes en el menú lateral."
    )
    st.stop()

# ─── Gap Analysis ─────────────────────────────────────────────────────────────
st.subheader("📊 Gap Analysis")

col_q, col_s = st.columns(2)
with col_q:
    st.markdown("**Fuente: Cuestionario IEC 62443**")
    if has_questionnaire:
        scores = score_responses(responses)
        questionnaire_gaps = compute_gaps(responses, zones, global_sl_target)
        st.metric("Security Level Alcanzado", f"SL {scores['overall_sl']}", delta=f"objetivo SL {global_sl_target}")
        st.metric("Brechas identificadas", len(questionnaire_gaps))
        fig_radar = build_radar_chart(scores["fr_scores"], scores["fr_achieved_sl"], global_sl_target)
        st.plotly_chart(fig_radar, use_container_width=True)
    else:
        questionnaire_gaps = []
        st.info("Sin datos de cuestionario.")

with col_s:
    st.markdown("**Fuente: Escáner de red**")
    if has_scanner:
        critical = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in all_findings if f.get("severity") == "HIGH")
        scanner_gaps = merge_gaps_from_findings(all_findings)
        st.metric("Hallazgos totales", len(all_findings))
        st.metric("Críticos / Altos", f"{critical} / {high}")
        st.metric("Brechas desde escáner", len(scanner_gaps))

        # Protocol breakdown
        proto_counts = {}
        for f in all_findings:
            p = f.get("protocol", "Otro")
            proto_counts[p] = proto_counts.get(p, 0) + 1

        import plotly.graph_objects as go
        fig = go.Figure(data=[go.Bar(
            x=list(proto_counts.keys()), y=list(proto_counts.values()),
            marker_color="#FF8800",
        )])
        fig.update_layout(paper_bgcolor="#0E0E0E", plot_bgcolor="#0E0E0E",
                          font=dict(color="#EEE"), height=280, margin=dict(l=20, r=20, t=30, b=60),
                          title="Hallazgos por protocolo")
        st.plotly_chart(fig, use_container_width=True)
    else:
        scanner_gaps = []
        st.info("Sin datos de escáner.")

# ─── Generate / Refresh Roadmap ──────────────────────────────────────────────
st.divider()
col_gen, col_opt = st.columns([2, 1])
with col_gen:
    st.subheader("🔄 Generar Roadmap")
    st.caption("Combina los gaps del cuestionario con los hallazgos del escáner para generar el plan de mejora.")
with col_opt:
    target_sl_override = st.select_slider(
        "SL objetivo para el roadmap",
        options=[1, 2, 3, 4],
        value=global_sl_target,
        format_func=lambda x: f"SL {x}",
    )

if st.button("▶ Generar/Actualizar Roadmap", type="primary"):
    all_gaps = questionnaire_gaps + scanner_gaps
    with st.spinner("Generando roadmap..."):
        # Clear existing roadmap items for this session
        delete_roadmap_items(session_id)
        roadmap_items = generate_roadmap(
            session_id=session_id,
            questionnaire_gaps=all_gaps,
            scanner_findings=all_findings,
            zones=zones,
            global_sl_target=target_sl_override,
        )
        for item in roadmap_items:
            upsert_roadmap_item(item)
    st.success(f"✅ Roadmap generado con {len(roadmap_items)} ítems de mejora.")
    st.rerun()

# ─── Show Roadmap ─────────────────────────────────────────────────────────────
roadmap_items = get_roadmap_items(session_id)

if not roadmap_items:
    st.info("Hacé clic en 'Generar Roadmap' para crear el plan de mejora.")
    st.stop()

st.divider()
st.subheader(f"📋 Plan de Mejora ({len(roadmap_items)} ítems)")

# Phase filter
phase_filter = st.multiselect(
    "Filtrar por fase",
    options=[1, 2, 3],
    default=[1, 2, 3],
    format_func=lambda x: {1: "Fase 1 – Mejoras Inmediatas", 2: "Fase 2 – Mediano Plazo", 3: "Fase 3 – Estratégico"}[x],
)

filtered_items = [item for item in roadmap_items if item.get("phase") in phase_filter]

# ─── Gantt Chart ──────────────────────────────────────────────────────────────
fig_gantt = build_gantt_chart(filtered_items)
st.plotly_chart(fig_gantt, use_container_width=True)

# ─── CSF Coverage ─────────────────────────────────────────────────────────────
csf_coverage = compute_csf_coverage(roadmap_items)
col_csf1, col_csf2 = st.columns([1, 2])
with col_csf1:
    fig_csf = build_csf_donut(csf_coverage)
    st.plotly_chart(fig_csf, use_container_width=True)
with col_csf2:
    st.markdown("**Cobertura NIST CSF**")
    for fn, pct in csf_coverage.items():
        color = "green" if pct >= 0.7 else ("orange" if pct >= 0.4 else "red")
        st.markdown(f"**{fn}**: {pct*100:.0f}%")
        st.progress(pct)

# ─── Roadmap Detail Table ─────────────────────────────────────────────────────
st.divider()
st.subheader("Detalle del Roadmap")

PHASE_BADGES = {1: "🟢 F1", 2: "🟡 F2", 3: "🔵 F3"}
STATUS_OPTIONS = {
    "not_started":  "⬜ No iniciado",
    "in_progress":  "🔄 En progreso",
    "completed":    "✅ Completado",
}

# Totals per phase
for phase in [1, 2, 3]:
    phase_items = [i for i in filtered_items if i.get("phase") == phase]
    if not phase_items:
        continue
    phase_names = {1: "Fase 1 – Mejoras Inmediatas (< 30 días)",
                   2: "Fase 2 – Mediano Plazo (30-90 días)",
                   3: "Fase 3 – Estratégico (> 90 días)"}
    phase_effort = sum(i.get("effort_days", 0) for i in phase_items)
    st.markdown(f"### {PHASE_BADGES[phase]} {phase_names[phase]} — {len(phase_items)} ítems, ~{phase_effort} días")

    for item in phase_items:
        priority = item.get("priority_score", 0)
        effort = item.get("effort_days", 0)
        status = item.get("status", "not_started")
        csf = ", ".join(item.get("csf_functions", []))
        nist = ", ".join(item.get("nist_controls", [])[:3])
        purdue = ", ".join([f"L{l}" for l in item.get("purdue_levels", [])])

        with st.expander(
            f"{STATUS_OPTIONS[status]} **{item['title']}** | Prioridad: {priority:.0f}/100 | Esfuerzo: {effort} días"
        ):
            st.markdown(item.get("description", ""))

            col_meta1, col_meta2, col_meta3 = st.columns(3)
            col_meta1.markdown(f"**Fase:** {phase}\n\n**Prioridad:** {priority:.0f}/100")
            col_meta2.markdown(f"**Esfuerzo:** {effort} días\n\n**Niveles Purdue:** {purdue or 'N/A'}")
            col_meta3.markdown(f"**CSF:** {csf}\n\n**NIST:** {nist}")

            # Status update
            new_status = st.selectbox(
                "Actualizar estado",
                options=list(STATUS_OPTIONS.keys()),
                format_func=lambda x: STATUS_OPTIONS[x],
                index=list(STATUS_OPTIONS.keys()).index(status),
                key=f"status_{item['item_id']}",
            )
            if new_status != status:
                update_roadmap_status(item["item_id"], new_status)
                st.rerun()

# ─── Export ───────────────────────────────────────────────────────────────────
st.divider()
st.markdown("**Exportar roadmap**")

roadmap_export = pd.DataFrame([{
    "Fase": i.get("phase"),
    "Prioridad": round(i.get("priority_score", 0)),
    "Título": i.get("title"),
    "Descripción": i.get("description", "")[:200],
    "Esfuerzo (días)": i.get("effort_days"),
    "Estado": i.get("status"),
    "CSF": ", ".join(i.get("csf_functions", [])),
    "NIST Controls": ", ".join(i.get("nist_controls", [])),
    "Niveles Purdue": ", ".join([f"L{l}" for l in i.get("purdue_levels", [])]),
} for i in roadmap_items])

csv = roadmap_export.to_csv(index=False).encode("utf-8")
st.download_button(
    "⬇️ Descargar roadmap como CSV",
    data=csv,
    file_name=f"roadmap_{session_id[:8]}.csv",
    mime="text/csv",
)
