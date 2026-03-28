"""
Roadmap Gantt chart and CSF coverage donut chart.
"""
import plotly.graph_objects as go
import plotly.express as px


PHASE_COLORS = {
    1: "#00CC66",   # Green: quick wins
    2: "#FFAA00",   # Amber: medium term
    3: "#4488FF",   # Blue: strategic
}

PHASE_NAMES = {
    1: "Fase 1 – Mejoras Inmediatas",
    2: "Fase 2 – Mediano Plazo",
    3: "Fase 3 – Estratégico",
}

STATUS_SYMBOLS = {
    "not_started":  "●",
    "in_progress":  "▶",
    "completed":    "✓",
}


def build_gantt_chart(roadmap_items: list[dict]) -> go.Figure:
    """
    Build a horizontal bar (Gantt-style) chart for the roadmap.

    Items are ordered by phase, then priority descending.
    """
    if not roadmap_items:
        fig = go.Figure()
        fig.add_annotation(
            x=0.5, y=0.5, xref="paper", yref="paper",
            text="No hay ítems de roadmap generados aún.",
            showarrow=False, font=dict(size=14, color="#888"),
        )
        fig.update_layout(paper_bgcolor="#0E0E0E", plot_bgcolor="#0E0E0E", font=dict(color="#EEE"))
        return fig

    sorted_items = sorted(roadmap_items, key=lambda x: (x.get("phase", 1), -x.get("priority_score", 0)))

    # Assign cumulative start day per phase
    phase_day: dict[int, int] = {1: 0, 2: 0, 3: 0}
    bars = []
    for item in sorted_items:
        phase = item.get("phase", 1)
        effort = item.get("effort_days", 10)
        start = phase_day[phase]
        bars.append({
            **item,
            "_start": start,
            "_end": start + effort,
        })
        phase_day[phase] += effort + 5  # 5-day buffer between items

    # Total timeline per phase (offset phases)
    phase_offsets = {1: 0, 2: phase_day[1] + 10, 3: phase_day[1] + phase_day[2] + 20}

    y_labels = []
    x_starts = []
    x_ends = []
    bar_colors = []
    hover_texts = []

    for bar in bars:
        phase = bar.get("phase", 1)
        offset = phase_offsets[phase]
        status_sym = STATUS_SYMBOLS.get(bar.get("status", "not_started"), "●")
        label = f"{status_sym} [{PHASE_NAMES[phase][:10]}] {bar['title'][:45]}"
        y_labels.append(label)
        x_starts.append(bar["_start"] + offset)
        x_ends.append(bar["_end"] + offset)
        bar_colors.append(PHASE_COLORS[phase])
        csf = ", ".join(bar.get("csf_functions", []))
        nist = ", ".join(bar.get("nist_controls", [])[:3])
        hover_texts.append(
            f"<b>{bar['title']}</b><br>"
            f"Fase: {phase} | Prioridad: {bar.get('priority_score', 0):.1f}/100<br>"
            f"Esfuerzo: {bar.get('effort_days', 0)} días<br>"
            f"Estado: {bar.get('status', 'not_started')}<br>"
            f"CSF: {csf}<br>"
            f"NIST: {nist}"
        )

    # Build horizontal bars using Scatter with error bars trick
    fig = go.Figure()
    for i, (yl, xs, xe, color, hover) in enumerate(zip(y_labels, x_starts, x_ends, bar_colors, hover_texts)):
        fig.add_trace(go.Bar(
            x=[xe - xs],
            y=[yl],
            base=[xs],
            orientation="h",
            marker=dict(color=color, line=dict(width=1, color="#111")),
            hovertext=hover,
            hoverinfo="text",
            name=PHASE_NAMES.get(bars[i].get("phase", 1), ""),
            showlegend=False,
        ))

    # Phase legend
    for ph, color in PHASE_COLORS.items():
        fig.add_trace(go.Bar(
            x=[None], y=[None],
            orientation="h",
            marker=dict(color=color),
            name=PHASE_NAMES[ph],
            showlegend=True,
        ))

    fig.update_layout(
        title="Roadmap de Mejora — Planificación por Fases",
        xaxis=dict(title="Días desde inicio", gridcolor="#333"),
        yaxis=dict(autorange="reversed", gridcolor="#222"),
        barmode="overlay",
        paper_bgcolor="#0E0E0E",
        plot_bgcolor="#0E0E0E",
        font=dict(color="#EEEEEE"),
        height=max(400, 35 * len(sorted_items) + 120),
        legend=dict(orientation="h", yanchor="bottom", y=-0.12),
        margin=dict(l=20, r=20, t=60, b=80),
    )

    return fig


def build_csf_donut(csf_coverage: dict) -> go.Figure:
    """
    Build a donut chart showing NIST CSF function coverage.

    Args:
        csf_coverage: {"Identify": 0.6, "Protect": 0.8, ...}
    """
    functions = list(csf_coverage.keys())
    values = [round(v * 100, 1) for v in csf_coverage.values()]
    colors = ["#4488FF", "#00CC66", "#FFAA00", "#FF6644", "#AA44FF"]

    fig = go.Figure(data=go.Pie(
        labels=functions,
        values=values,
        hole=0.5,
        marker=dict(colors=colors[:len(functions)]),
        texttemplate="%{label}<br>%{value:.0f}%",
        hovertemplate="%{label}: %{value:.1f}% cobertura<extra></extra>",
    ))

    fig.update_layout(
        title="Cobertura NIST CSF por Función",
        paper_bgcolor="#0E0E0E",
        font=dict(color="#EEEEEE"),
        height=360,
        margin=dict(l=20, r=20, t=60, b=20),
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.1),
        annotations=[dict(
            text="NIST CSF",
            x=0.5, y=0.5,
            font=dict(size=14, color="#EEEEEE"),
            showarrow=False,
        )],
    )

    return fig


def build_findings_severity_chart(findings: list[dict]) -> go.Figure:
    """Bar chart of finding counts by severity and protocol."""
    from collections import defaultdict

    if not findings:
        fig = go.Figure()
        fig.add_annotation(x=0.5, y=0.5, xref="paper", yref="paper",
                           text="Sin hallazgos", showarrow=False, font=dict(color="#888"))
        fig.update_layout(paper_bgcolor="#0E0E0E", plot_bgcolor="#0E0E0E", font=dict(color="#EEE"), height=200)
        return fig

    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_colors = {"CRITICAL": "#FF2222", "HIGH": "#FF8800", "MEDIUM": "#FFCC00", "LOW": "#44AAFF", "INFO": "#888888"}
    counts = defaultdict(int)
    for f in findings:
        counts[f.get("severity", "INFO")] += 1

    fig = go.Figure(data=[
        go.Bar(
            x=[sev for sev in sev_order if sev in counts],
            y=[counts[sev] for sev in sev_order if sev in counts],
            marker_color=[sev_colors[sev] for sev in sev_order if sev in counts],
            text=[counts[sev] for sev in sev_order if sev in counts],
            textposition="outside",
        )
    ])
    fig.update_layout(
        title="Hallazgos por Severidad",
        xaxis_title="Severidad",
        yaxis_title="Cantidad",
        paper_bgcolor="#0E0E0E",
        plot_bgcolor="#0E0E0E",
        font=dict(color="#EEEEEE"),
        height=280,
        margin=dict(l=40, r=20, t=50, b=40),
    )
    return fig
