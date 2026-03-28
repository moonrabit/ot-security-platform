"""
PDF Report Generator using ReportLab.
Produces a professional OT Security Assessment Report.
"""
from __future__ import annotations
import io
from datetime import datetime
from pathlib import Path

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, HRFlowable,
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


SEVERITY_COLORS_RL = {
    "CRITICAL": colors.HexColor("#CC2222"),
    "HIGH":     colors.HexColor("#CC7700"),
    "MEDIUM":   colors.HexColor("#CCCC00"),
    "LOW":      colors.HexColor("#4488CC"),
    "INFO":     colors.HexColor("#888888"),
}

PHASE_COLORS_RL = {
    1: colors.HexColor("#00AA55"),
    2: colors.HexColor("#FF9900"),
    3: colors.HexColor("#4488FF"),
}


def generate_pdf_report(
    session: dict,
    zones: list[dict],
    conduits: list[dict],
    responses: list[dict],
    fr_scores: dict,
    fr_achieved_sl: dict,
    overall_sl: int,
    overall_pct: float,
    questionnaire_gaps: list[dict],
    scan_sessions: list[dict],
    findings: list[dict],
    devices: list[dict],
    roadmap_items: list[dict],
    csf_coverage: dict,
    global_sl_target: int = 2,
) -> bytes:
    """
    Generate the full PDF assessment report.
    Returns PDF bytes.
    """
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError("ReportLab no está instalado. Ejecutá: pip install reportlab")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm,
        title="OT Security Assessment Report",
    )

    styles = getSampleStyleSheet()
    style_h1 = ParagraphStyle("H1", parent=styles["Heading1"], fontSize=22, textColor=colors.HexColor("#0078C8"), spaceAfter=12)
    style_h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=16, textColor=colors.HexColor("#005590"), spaceAfter=8)
    style_h3 = ParagraphStyle("H3", parent=styles["Heading3"], fontSize=13, textColor=colors.HexColor("#333333"), spaceAfter=6)
    style_body = ParagraphStyle("Body", parent=styles["Normal"], fontSize=10, leading=14, spaceAfter=6)
    style_caption = ParagraphStyle("Caption", parent=styles["Normal"], fontSize=8, textColor=colors.grey, spaceAfter=4)
    style_center = ParagraphStyle("Center", parent=styles["Normal"], alignment=TA_CENTER)
    style_bold = ParagraphStyle("Bold", parent=styles["Normal"], fontSize=10, fontName="Helvetica-Bold")

    story = []
    now = datetime.utcnow().strftime("%d/%m/%Y")

    # ─── COVER PAGE ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 3*cm))
    story.append(Paragraph("INFORME DE EVALUACIÓN DE SEGURIDAD OT", ParagraphStyle(
        "Cover", parent=styles["Title"], fontSize=26, alignment=TA_CENTER,
        textColor=colors.HexColor("#0078C8"), spaceAfter=20,
    )))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0078C8")))
    story.append(Spacer(1, 0.5*cm))

    cover_data = [
        ["Organización:", session.get("org_name", "N/A")],
        ["Sitio / Planta:", session.get("site_name", "N/A")],
        ["Fecha de evaluación:", now],
        ["Marco de referencia:", "IEC 62443 · Modelo Purdue · NIST CSF"],
        ["Security Level objetivo:", f"SL {global_sl_target}"],
        ["Security Level alcanzado:", f"SL {overall_sl}"],
    ]
    cover_tbl = Table(cover_data, colWidths=[5*cm, 10*cm])
    cover_tbl.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 11),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#F0F0F0")]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(cover_tbl)
    story.append(Spacer(1, 2*cm))

    # Risk posture badge
    if overall_sl >= global_sl_target:
        posture_text = f"CUMPLE EL OBJETIVO (SL {overall_sl}/{global_sl_target})"
        posture_color = colors.HexColor("#00AA55")
    elif overall_sl == global_sl_target - 1:
        posture_text = f"BRECHA MODERADA (SL {overall_sl}/{global_sl_target})"
        posture_color = colors.HexColor("#FF9900")
    else:
        posture_text = f"BRECHA SIGNIFICATIVA (SL {overall_sl}/{global_sl_target})"
        posture_color = colors.HexColor("#CC2222")

    story.append(Paragraph(f"<b>POSTURA DE RIESGO: {posture_text}</b>",
                            ParagraphStyle("Posture", parent=styles["Normal"],
                                           fontSize=14, alignment=TA_CENTER,
                                           textColor=posture_color, spaceAfter=12)))
    story.append(PageBreak())

    # ─── EXECUTIVE SUMMARY ─────────────────────────────────────────────────────
    story.append(Paragraph("1. Resumen Ejecutivo", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CCCCCC")))
    story.append(Spacer(1, 0.3*cm))

    critical_findings = [f for f in findings if f.get("severity") == "CRITICAL"]
    high_findings = [f for f in findings if f.get("severity") == "HIGH"]

    exec_text = f"""
    Se realizó una evaluación de ciberseguridad para la planta <b>{session.get('site_name', '') or session.get('org_name', '')}</b>
    basada en el estándar IEC 62443, el Modelo de Referencia Purdue y el Marco de Ciberseguridad NIST (CSF).
    La evaluación incluyó un cuestionario estructurado de {len(responses)} respuestas distribuidas en los
    7 Requisitos Fundamentales (FR) de la norma IEC 62443-3-3, complementado con el análisis pasivo de
    tráfico de red que procesó {sum(s.get('total_packets', 0) for s in scan_sessions):,} paquetes.
    <br/><br/>
    El Security Level alcanzado globalmente es <b>SL {overall_sl}</b> contra un objetivo de <b>SL {global_sl_target}</b>,
    con un score de cumplimiento del <b>{overall_pct*100:.1f}%</b>.
    El análisis de tráfico identificó <b>{len(findings)} hallazgos</b>, de los cuales
    <b>{len(critical_findings)} son críticos</b> y <b>{len(high_findings)} son de severidad alta</b>.
    Se generaron <b>{len(roadmap_items)} ítems de mejora</b> organizados en 3 fases.
    """
    story.append(Paragraph(exec_text, style_body))
    story.append(Spacer(1, 0.5*cm))

    # Top 5 critical findings
    if critical_findings or high_findings:
        story.append(Paragraph("Hallazgos más críticos:", style_h3))
        top_findings = (critical_findings + high_findings)[:5]
        top_data = [["Severidad", "Protocolo", "Descripción", "IEC 62443"]]
        for f in top_findings:
            top_data.append([
                f.get("severity", ""),
                f.get("protocol", ""),
                (f.get("description", "")[:80] + "...") if len(f.get("description","")) > 80 else f.get("description",""),
                f.get("iec62443_ref", ""),
            ])
        top_tbl = Table(top_data, colWidths=[2*cm, 3*cm, 9*cm, 2*cm])
        top_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#005590")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        # Color severity column
        sev_colors_map = {"CRITICAL": colors.HexColor("#FFE0E0"), "HIGH": colors.HexColor("#FFF0E0")}
        for row_idx, f in enumerate(top_findings, start=1):
            bg = sev_colors_map.get(f.get("severity", ""), colors.white)
            top_tbl.setStyle(TableStyle([("BACKGROUND", (0, row_idx), (0, row_idx), bg)]))
        story.append(top_tbl)

    story.append(PageBreak())

    # ─── ASSESSMENT RESULTS ────────────────────────────────────────────────────
    story.append(Paragraph("2. Resultados del Assessment IEC 62443", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CCCCCC")))
    story.append(Spacer(1, 0.3*cm))

    from config import FOUNDATIONAL_REQUIREMENTS
    fr_data = [["FR", "Nombre", "SL Objetivo", "SL Alcanzado", "Score", "Estado"]]
    for fr in range(1, 8):
        fr_info = FOUNDATIONAL_REQUIREMENTS[fr]
        achieved = fr_achieved_sl.get(fr, 0)
        score = fr_scores.get(fr, 0)
        gap = global_sl_target - achieved
        estado = "Cumple" if gap <= 0 else ("Brecha mínima" if gap == 1 else "Brecha crítica")
        fr_data.append([
            fr_info["code"],
            fr_info["name"][:45],
            str(global_sl_target),
            str(achieved),
            f"{score*100:.0f}%",
            estado,
        ])
    fr_tbl = Table(fr_data, colWidths=[1.5*cm, 6.5*cm, 2*cm, 2.5*cm, 1.5*cm, 3*cm])
    fr_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#005590")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F0F0F0")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    # Color status column
    for row_idx in range(1, 8):
        estado = fr_data[row_idx][5]
        bg = colors.HexColor("#E0FFE0") if "Cumple" in estado else (
            colors.HexColor("#FFF0CC") if "mínima" in estado else colors.HexColor("#FFE0E0")
        )
        fr_tbl.setStyle(TableStyle([("BACKGROUND", (5, row_idx), (5, row_idx), bg)]))
    story.append(fr_tbl)
    story.append(PageBreak())

    # ─── SCANNER FINDINGS ──────────────────────────────────────────────────────
    if findings:
        story.append(Paragraph("3. Hallazgos del Escáner de Protocolos OT", style_h1))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CCCCCC")))
        story.append(Spacer(1, 0.3*cm))

        # Stats
        from collections import Counter
        sev_counts = Counter(f.get("severity", "INFO") for f in findings)
        sev_text = " | ".join(f"**{sev}**: {cnt}" for sev, cnt in
                               sorted(sev_counts.items(), key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x[0])))
        story.append(Paragraph(f"Total de hallazgos: {len(findings)} — {sev_text}", style_body))

        findings_data = [["Severidad", "Protocolo", "Tipo", "Origen → Destino", "IEC 62443"]]
        for f in sorted(findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x.get("severity","INFO"))):
            findings_data.append([
                f.get("severity", ""),
                f.get("protocol", "")[:15],
                f.get("finding_type", "")[:20],
                f"{f.get('src_ip','')} → {f.get('dst_ip','')}",
                f.get("iec62443_ref", ""),
            ])
        f_tbl = Table(findings_data, colWidths=[2*cm, 3.5*cm, 3.5*cm, 4.5*cm, 2.5*cm])
        f_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#005590")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(f_tbl)
        story.append(PageBreak())

    # ─── ROADMAP ───────────────────────────────────────────────────────────────
    story.append(Paragraph("4. Roadmap de Mejora", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CCCCCC")))
    story.append(Spacer(1, 0.3*cm))

    phase_names = {
        1: "Fase 1 – Mejoras Inmediatas (0-30 días)",
        2: "Fase 2 – Mediano Plazo (1-3 meses)",
        3: "Fase 3 – Estratégico (3-12 meses)",
    }
    for phase in [1, 2, 3]:
        phase_items = [i for i in roadmap_items if i.get("phase") == phase]
        if not phase_items:
            continue
        story.append(Paragraph(phase_names[phase], style_h2))
        rm_data = [["Prioridad", "Ítem", "Esfuerzo", "CSF", "NIST"]]
        for item in phase_items:
            rm_data.append([
                f"{item.get('priority_score', 0):.0f}/100",
                item.get("title", "")[:60],
                f"{item.get('effort_days', 0)} días",
                ", ".join(item.get("csf_functions", []))[:20],
                ", ".join(item.get("nist_controls", [])[:2]),
            ])
        rm_tbl = Table(rm_data, colWidths=[2*cm, 7*cm, 2*cm, 2.5*cm, 2.5*cm])
        rm_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PHASE_COLORS_RL.get(phase, colors.grey)),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(rm_tbl)
        story.append(Spacer(1, 0.4*cm))

    story.append(PageBreak())

    # ─── APPENDIX: Methodology ─────────────────────────────────────────────────
    story.append(Paragraph("5. Apéndice: Marco Metodológico", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CCCCCC")))
    story.append(Spacer(1, 0.3*cm))

    from config import FOUNDATIONAL_REQUIREMENTS, NIST_CSF_FUNCTIONS
    story.append(Paragraph("IEC 62443 – Requisitos Fundamentales", style_h2))
    fr_ref_data = [["FR", "Nombre", "Descripción"]]
    for fr, info in FOUNDATIONAL_REQUIREMENTS.items():
        fr_ref_data.append([info["code"], info["name"][:30], info["description"][:80]])
    fr_ref_tbl = Table(fr_ref_data, colWidths=[1.5*cm, 4.5*cm, 10*cm])
    fr_ref_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#005590")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F0F0F0")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(fr_ref_tbl)

    # Footer note
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph(
        f"Informe generado el {now} por la Plataforma de Evaluación de Seguridad OT. "
        "Este informe es confidencial y de uso exclusivo del destinatario.",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=7, textColor=colors.grey, alignment=TA_CENTER)
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()
