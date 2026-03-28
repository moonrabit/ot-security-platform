"""
Módulo 1: Assessment IEC 62443
Cuestionario estructurado por FR con diseño de zonas/conduits.
"""
from auth import require_auth

require_auth()

import streamlit as st
import uuid
from datetime import datetime

from db.database import (
    init_db, get_session, get_zones, get_conduits, get_responses,
    upsert_zone, upsert_conduit, delete_zone, delete_conduit,
    upsert_response, get_response, update_zone_sl,
)
from core.questionnaire_engine import (
    load_questions, get_questions_by_fr, score_responses,
    compute_gaps, get_completion_stats,
)
from visualizations.radar_chart import build_radar_chart
from visualizations.sl_heatmap import build_simple_sl_heatmap
from config import (
    FOUNDATIONAL_REQUIREMENTS, SECURITY_LEVELS, PURDUE_LEVELS,
    ASSET_TYPES_BY_LEVEL, INDUSTRY_SECTORS,
)

init_db()

st.set_page_config(page_title="Assessment IEC 62443", page_icon="📋", layout="wide")
st.title("📋 Módulo 1: Assessment IEC 62443")

# ─── Session guard ─────────────────────────────────────────────────────────────
if not st.session_state.get("session_id"):
    st.warning("Selecciona o crea una sesión desde la página principal.")
    st.stop()

session_id = st.session_state.session_id
session = get_session(session_id)
if not session:
    st.error("Sesión no encontrada. Volvé a la página principal.")
    st.stop()

st.caption(f"Sesión: **{session['org_name']}** | {session['site_name']} | ID: `{session_id[:8]}`")
st.divider()

# ─── Tabs ──────────────────────────────────────────────────────────────────────
tab_zones, tab_questionnaire, tab_scores = st.tabs([
    "🗺️ Zonas y Conduits",
    "📝 Cuestionario",
    "📊 Resultados",
])

# ════════════════════════════════════════════════════════════════════════
# TAB 1: ZONE/CONDUIT DESIGNER
# ════════════════════════════════════════════════════════════════════════
with tab_zones:
    st.subheader("Diseño de Zonas y Conduits")
    col_zone, col_conduit = st.columns([1, 1])

    with col_zone:
        st.markdown("#### Zonas de Seguridad")
        zones = get_zones(session_id)

        with st.expander("➕ Agregar zona", expanded=len(zones) == 0):
            z_name = st.text_input("Nombre de la zona", placeholder="Ej: Zona PLC Línea 1")
            z_level = st.selectbox(
                "Nivel Purdue",
                options=list(PURDUE_LEVELS.keys()),
                format_func=lambda x: PURDUE_LEVELS[x],
                index=1,
                key="new_zone_level",
            )
            z_sl_target = st.select_slider(
                "Security Level objetivo",
                options=[1, 2, 3, 4],
                value=2,
                format_func=lambda x: f"SL {x}",
                key="new_zone_sl",
            )
            z_assets = st.multiselect(
                "Tipos de activos en esta zona",
                options=ASSET_TYPES_BY_LEVEL.get(z_level, []),
                key="new_zone_assets",
            )
            if st.button("Agregar zona", type="primary", disabled=not z_name):
                upsert_zone({
                    "zone_id": str(uuid.uuid4()),
                    "session_id": session_id,
                    "name": z_name,
                    "purdue_level": z_level,
                    "sl_target": z_sl_target,
                    "sl_achieved": 0.0,
                    "asset_types": z_assets,
                })
                st.rerun()

        if zones:
            for zone in zones:
                with st.container():
                    c1, c2, c3 = st.columns([3, 1, 1])
                    c1.markdown(f"**{zone['name']}** — L{zone['purdue_level']} | SL objetivo: {zone['sl_target']}")
                    c2.markdown(f"SL alcanzado: **{zone.get('sl_achieved', 0):.1f}**")
                    if c3.button("🗑️", key=f"del_zone_{zone['zone_id']}"):
                        delete_zone(zone["zone_id"])
                        st.rerun()
        else:
            st.info("No hay zonas definidas. Agregá al menos una para habilitar el análisis por zona.")

    with col_conduit:
        st.markdown("#### Conduits (enlaces entre zonas)")
        zones = get_zones(session_id)
        conduits = get_conduits(session_id)
        zone_options = {z["zone_id"]: z["name"] for z in zones}

        with st.expander("➕ Agregar conduit", expanded=False):
            if len(zones) < 2:
                st.info("Necesitás al menos 2 zonas para definir un conduit.")
            else:
                c_src = st.selectbox("Zona origen", options=list(zone_options.keys()),
                                     format_func=lambda x: zone_options[x], key="c_src")
                c_dst = st.selectbox("Zona destino", options=list(zone_options.keys()),
                                     format_func=lambda x: zone_options[x], key="c_dst",
                                     index=min(1, len(zones)-1))
                c_protocols = st.multiselect(
                    "Protocolos en el conduit",
                    options=["Modbus/TCP", "DNP3", "EtherNet/IP", "OPC-UA", "BACnet",
                             "IEC 104", "S7comm", "PROFINET", "HTTP/HTTPS", "SSH", "Otro"],
                )
                c_fw = st.checkbox("¿Tiene firewall?")
                c_dmz = st.checkbox("¿Pasa por DMZ?")
                if st.button("Agregar conduit", type="primary"):
                    upsert_conduit({
                        "conduit_id": str(uuid.uuid4()),
                        "session_id": session_id,
                        "source_zone": c_src,
                        "dest_zone": c_dst,
                        "protocols": c_protocols,
                        "has_firewall": int(c_fw),
                        "has_dmz": int(c_dmz),
                    })
                    st.rerun()

        if conduits:
            for c in conduits:
                src_name = zone_options.get(c.get("source_zone", ""), "?")
                dst_name = zone_options.get(c.get("dest_zone", ""), "?")
                fw = "✅ Firewall" if c.get("has_firewall") else "❌ Sin firewall"
                dmz = "✅ DMZ" if c.get("has_dmz") else ""
                protos = ", ".join(c.get("protocols", []))
                cc1, cc2 = st.columns([4, 1])
                cc1.markdown(f"**{src_name}** → **{dst_name}** | {fw} {dmz}<br><small>{protos}</small>",
                             unsafe_allow_html=True)
                if cc2.button("🗑️", key=f"del_cond_{c['conduit_id']}"):
                    delete_conduit(c["conduit_id"])
                    st.rerun()

    # Zone-based conduit risk summary
    if conduits:
        st.divider()
        st.markdown("**Riesgos de conduits sin protección:**")
        risky = [c for c in conduits if not c.get("has_firewall")]
        if risky:
            for c in risky:
                src = zone_options.get(c.get("source_zone", ""), "?")
                dst = zone_options.get(c.get("dest_zone", ""), "?")
                st.warning(f"⚠️ Conduit **{src} → {dst}** sin firewall")
        else:
            st.success("✅ Todos los conduits tienen firewall configurado.")


# ════════════════════════════════════════════════════════════════════════
# TAB 2: QUESTIONNAIRE
# ════════════════════════════════════════════════════════════════════════
with tab_questionnaire:
    zones = get_zones(session_id)
    responses = get_responses(session_id)
    completion = get_completion_stats(responses)

    # Global SL target
    col_sl, col_sector = st.columns([1, 2])
    with col_sl:
        global_sl_target = st.select_slider(
            "Security Level objetivo (global)",
            options=[1, 2, 3, 4],
            value=st.session_state.get("global_sl_target", 2),
            format_func=lambda x: f"SL {x} – {SECURITY_LEVELS[x][:50]}...",
        )
        st.session_state["global_sl_target"] = global_sl_target
    with col_sector:
        sector = st.selectbox("Sector industrial", options=INDUSTRY_SECTORS)

    # Zone selector for per-zone answering
    zone_options_q = {"": "Global (sin zona específica)"}
    for z in zones:
        zone_options_q[z["zone_id"]] = z["name"]
    selected_zone = st.selectbox(
        "Responder para:",
        options=list(zone_options_q.keys()),
        format_func=lambda x: zone_options_q[x],
    )

    # FR tabs
    fr_tabs = st.tabs([
        f"FR{fr} ({completion[fr]['answered']}/{completion[fr]['total']})"
        for fr in range(1, 8)
    ])

    ANSWER_LABELS = {
        "fully":     "✅ Completamente implementado",
        "partially": "⚠️ Parcialmente implementado",
        "no":        "❌ No implementado",
        "na":        "N/A – No aplica",
    }

    for idx, fr in enumerate(range(1, 8)):
        with fr_tabs[idx]:
            fr_info = FOUNDATIONAL_REQUIREMENTS[fr]
            st.markdown(f"**{fr_info['code']}: {fr_info['name']}**")
            st.caption(fr_info["description"])

            pct_done = completion[fr]["pct"]
            st.progress(pct_done, text=f"Completado: {pct_done*100:.0f}%")

            questions = get_questions_by_fr(fr)
            for q in questions:
                with st.container():
                    # Get existing answer
                    existing = get_response(session_id, q["question_id"], selected_zone)
                    current_answer = existing["answer"] if existing else "no"
                    current_evidence = existing.get("evidence_note", "") if existing else ""

                    col_q, col_a = st.columns([3, 1])
                    with col_q:
                        st.markdown(f"**{q['sr_ref']}**: {q['text']}")
                        with st.expander("ℹ️ Guía de evaluación", expanded=False):
                            st.caption(q.get("guidance", ""))
                            sl_rel = q.get("sl_relevance", {})
                            if sl_rel:
                                for sl_k, sl_v in sl_rel.items():
                                    st.caption(f"SL{sl_k}: {sl_v}")

                    with col_a:
                        answer = st.selectbox(
                            "Respuesta",
                            options=list(ANSWER_LABELS.keys()),
                            format_func=lambda x: ANSWER_LABELS[x],
                            index=list(ANSWER_LABELS.keys()).index(current_answer),
                            key=f"ans_{q['question_id']}_{selected_zone}",
                            label_visibility="collapsed",
                        )

                    # Evidence note
                    evidence = st.text_area(
                        "Nota/evidencia (opcional)",
                        value=current_evidence,
                        key=f"ev_{q['question_id']}_{selected_zone}",
                        label_visibility="collapsed",
                        placeholder=q["evidence_prompts"][0] if q.get("evidence_prompts") else "Agregar evidencia...",
                        height=50,
                    )

                    # Auto-save on change
                    if answer != current_answer or evidence != current_evidence:
                        response_id = existing["response_id"] if existing else str(uuid.uuid4())
                        upsert_response({
                            "response_id":  response_id,
                            "session_id":   session_id,
                            "question_id":  q["question_id"],
                            "fr_number":    fr,
                            "sl_target":    global_sl_target,
                            "answer":       answer,
                            "evidence_note": evidence,
                            "zone_id":      selected_zone,
                        })

                    st.markdown("---")


# ════════════════════════════════════════════════════════════════════════
# TAB 3: RESULTS / SCORING
# ════════════════════════════════════════════════════════════════════════
with tab_scores:
    responses = get_responses(session_id)
    zones = get_zones(session_id)

    if not responses:
        st.info("Completá al menos algunas preguntas del cuestionario para ver los resultados.")
        st.stop()

    global_sl_target = st.session_state.get("global_sl_target", 2)
    scores = score_responses(responses)
    fr_scores = scores["fr_scores"]
    fr_achieved_sl = scores["fr_achieved_sl"]
    overall_sl = scores["overall_sl"]
    overall_pct = scores["overall_pct"]

    # Update zone SL in DB
    for zone in zones:
        zone_responses = [r for r in responses if r.get("zone_id") == zone["zone_id"]]
        if zone_responses:
            zone_scores = score_responses(zone_responses)
            update_zone_sl(zone["zone_id"], zone_scores["overall_sl"])

    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Security Level Alcanzado", f"SL {overall_sl}", delta=f"{overall_sl - global_sl_target:+d} vs objetivo")
    col2.metric("Score Global", f"{overall_pct*100:.1f}%")
    col3.metric("Preguntas respondidas", scores["answered_count"])
    col4.metric("FR más débil",
                f"FR{min(fr_achieved_sl, key=fr_achieved_sl.get)} (SL{min(fr_achieved_sl.values())})")

    st.divider()

    col_radar, col_heat = st.columns([1, 1])

    with col_radar:
        fig_radar = build_radar_chart(fr_scores, fr_achieved_sl, global_sl_target)
        st.plotly_chart(fig_radar, use_container_width=True)

    with col_heat:
        fig_heat = build_simple_sl_heatmap(fr_achieved_sl, fr_scores, global_sl_target)
        st.plotly_chart(fig_heat, use_container_width=True)

    # Per-FR detail table
    st.subheader("Detalle por Requisito Fundamental")
    import pandas as pd
    fr_table = []
    for fr in range(1, 8):
        fr_info = FOUNDATIONAL_REQUIREMENTS[fr]
        achieved = fr_achieved_sl.get(fr, 0)
        score = fr_scores.get(fr, 0)
        gap = global_sl_target - achieved
        fr_table.append({
            "FR": fr_info["code"],
            "Nombre": fr_info["name"],
            "SL Objetivo": global_sl_target,
            "SL Alcanzado": achieved,
            "Score": f"{score*100:.0f}%",
            "Brecha": gap,
            "Estado": "✅ OK" if gap <= 0 else ("⚠️ Parcial" if gap == 1 else "❌ Crítico"),
        })
    df = pd.DataFrame(fr_table)
    st.dataframe(df, use_container_width=True, hide_index=True,
                 column_config={
                     "Brecha": st.column_config.NumberColumn(format="%d"),
                 })

    # Gap summary
    gaps = compute_gaps(responses, zones, global_sl_target)
    if gaps:
        st.subheader(f"Brechas identificadas ({len(gaps)} total)")
        gap_df = pd.DataFrame([{
            "Gap ID": g["gap_id"],
            "FR": f"FR{g['fr_number']}",
            "Zona": g["zone_id"][:12] if g["zone_id"] else "Global",
            "SL Actual": g["current_sl"],
            "SL Objetivo": g["target_sl"],
            "Magnitud": g["gap_magnitude"],
            "CSF": ", ".join(g.get("csf_functions", [])),
        } for g in gaps])
        st.dataframe(gap_df, use_container_width=True, hide_index=True)
