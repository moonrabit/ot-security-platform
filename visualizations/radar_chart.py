"""
FR1-FR7 Radar Chart for Security Level visualization.
"""
import plotly.graph_objects as go
from config import FOUNDATIONAL_REQUIREMENTS


def build_radar_chart(
    fr_scores: dict[int, float],
    fr_achieved_sl: dict[int, int],
    sl_target: int = 2,
    zone_name: str = "Global",
) -> go.Figure:
    """
    Build a Plotly radar chart showing achieved vs target SL per FR.

    Args:
        fr_scores: {1: 0.75, 2: 0.60, ...}  (0–1 percentage)
        fr_achieved_sl: {1: 2, 2: 1, ...}    (0–4 integer SL)
        sl_target: Overall target SL
        zone_name: Label for chart title
    """
    fr_labels = [
        f"FR{fr}<br>{FOUNDATIONAL_REQUIREMENTS[fr]['name'].split('(')[0].strip()}"
        for fr in range(1, 8)
    ]
    # Close the polygon
    fr_labels_closed = fr_labels + [fr_labels[0]]

    achieved_vals = [fr_achieved_sl.get(fr, 0) for fr in range(1, 8)]
    target_vals   = [sl_target] * 7
    achieved_vals_closed = achieved_vals + [achieved_vals[0]]
    target_vals_closed   = target_vals   + [target_vals[0]]
    score_vals = [fr_scores.get(fr, 0) * 4 for fr in range(1, 8)]  # scale to 0-4
    score_vals_closed = score_vals + [score_vals[0]]

    fig = go.Figure()

    # Target SL trace
    fig.add_trace(go.Scatterpolar(
        r=target_vals_closed,
        theta=fr_labels_closed,
        fill="none",
        name=f"Objetivo (SL {sl_target})",
        line=dict(color="#FF4444", width=2, dash="dash"),
        mode="lines+markers",
        marker=dict(size=6, color="#FF4444"),
    ))

    # Achieved SL trace
    fig.add_trace(go.Scatterpolar(
        r=achieved_vals_closed,
        theta=fr_labels_closed,
        fill="toself",
        fillcolor="rgba(0, 120, 200, 0.2)",
        name="SL Alcanzado",
        line=dict(color="#0078C8", width=2),
        mode="lines+markers",
        marker=dict(size=8, color="#0078C8"),
    ))

    # Raw score trace (0-4 scale)
    fig.add_trace(go.Scatterpolar(
        r=score_vals_closed,
        theta=fr_labels_closed,
        fill="none",
        name="Score % (escala 0-4)",
        line=dict(color="#00AA44", width=1, dash="dot"),
        mode="lines",
        visible="legendonly",
    ))

    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 4],
                tickvals=[0, 1, 2, 3, 4],
                ticktext=["SL0", "SL1", "SL2", "SL3", "SL4"],
                gridcolor="#444",
                linecolor="#444",
            ),
            angularaxis=dict(gridcolor="#333"),
            bgcolor="#1E1E1E",
        ),
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.15),
        title=dict(
            text=f"Security Level por Requisito Fundamental — {zone_name}",
            font=dict(size=16),
        ),
        paper_bgcolor="#0E0E0E",
        font=dict(color="#EEEEEE"),
        height=480,
        margin=dict(l=60, r=60, t=80, b=60),
    )

    return fig
