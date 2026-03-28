"""
Security Level heatmap: FR x Zone matrix.
"""
import plotly.graph_objects as go
from config import FOUNDATIONAL_REQUIREMENTS


def build_sl_heatmap(
    zones: list[dict],
    fr_scores_per_zone: dict,
    fr_achieved_sl_per_zone: dict,
    global_fr_scores: dict,
    global_fr_achieved_sl: dict,
    global_sl_target: int = 2,
) -> go.Figure:
    """
    Build a heatmap of SL achieved per FR per zone.

    Args:
        zones: list of zone dicts
        fr_scores_per_zone: {zone_id: {fr: score}}
        fr_achieved_sl_per_zone: {zone_id: {fr: sl}}
        global_fr_scores: {fr: score} for global responses
        global_fr_achieved_sl: {fr: sl}
        global_sl_target: int
    """
    fr_labels = [f"FR{i}" for i in range(1, 8)]
    zone_labels = ["Global"] + [z.get("name", z["zone_id"][:8]) for z in zones]

    # Build matrix: rows=FR, cols=zones
    z_matrix = []
    text_matrix = []
    for fr in range(1, 8):
        row_z = []
        row_text = []
        # Global column
        global_sl = global_fr_achieved_sl.get(fr, 0)
        row_z.append(global_sl)
        target = global_sl_target
        row_text.append(f"SL {global_sl}/{target}")

        # Per-zone columns
        for zone in zones:
            zid = zone["zone_id"]
            zone_sl = fr_achieved_sl_per_zone.get(zid, {}).get(fr, global_sl)
            zone_target = zone.get("sl_target", global_sl_target)
            row_z.append(zone_sl)
            row_text.append(f"SL {zone_sl}/{zone_target}")

        z_matrix.append(row_z)
        text_matrix.append(row_text)

    fig = go.Figure(data=go.Heatmap(
        z=z_matrix,
        x=zone_labels,
        y=fr_labels,
        zmin=0, zmax=4,
        colorscale=[
            [0.0,  "#CC2222"],
            [0.25, "#CC7700"],
            [0.5,  "#CCCC00"],
            [0.75, "#44AA44"],
            [1.0,  "#00DD88"],
        ],
        text=text_matrix,
        texttemplate="%{text}",
        textfont=dict(size=12, color="white"),
        hovertemplate="FR: %{y}<br>Zona: %{x}<br>%{text}<extra></extra>",
        showscale=True,
        colorbar=dict(
            title="SL",
            tickvals=[0, 1, 2, 3, 4],
            ticktext=["SL0", "SL1", "SL2", "SL3", "SL4"],
        ),
    ))

    fig.update_layout(
        title="Security Level Alcanzado por FR y Zona",
        xaxis=dict(title="Zona", gridcolor="#333"),
        yaxis=dict(title="Requisito Fundamental", autorange="reversed", gridcolor="#333"),
        paper_bgcolor="#0E0E0E",
        plot_bgcolor="#0E0E0E",
        font=dict(color="#EEEEEE"),
        height=400,
        margin=dict(l=60, r=60, t=60, b=60),
    )

    return fig


def build_simple_sl_heatmap(
    fr_achieved_sl: dict[int, int],
    fr_scores: dict[int, float],
    sl_target: int = 2,
) -> go.Figure:
    """Simple single-zone version."""
    fr_labels = [f"FR{i}\n{FOUNDATIONAL_REQUIREMENTS[i]['name'].split('(')[0][:20]}" for i in range(1, 8)]
    achieved = [[fr_achieved_sl.get(i, 0)] for i in range(1, 8)]
    text = [[f"SL {fr_achieved_sl.get(i, 0)}/{sl_target}\n({fr_scores.get(i, 0)*100:.0f}%)"] for i in range(1, 8)]

    fig = go.Figure(data=go.Heatmap(
        z=achieved,
        x=["Evaluación Global"],
        y=fr_labels,
        zmin=0, zmax=4,
        colorscale=[
            [0.0, "#CC2222"],
            [0.5, "#CCCC00"],
            [1.0, "#00DD88"],
        ],
        text=text,
        texttemplate="%{text}",
        textfont=dict(size=11),
        showscale=True,
        colorbar=dict(tickvals=[0,1,2,3,4], ticktext=["SL0","SL1","SL2","SL3","SL4"]),
    ))
    fig.update_layout(
        title="Security Level por FR",
        paper_bgcolor="#0E0E0E",
        plot_bgcolor="#0E0E0E",
        font=dict(color="#EEEEEE"),
        height=380,
        margin=dict(l=120, r=60, t=50, b=50),
        yaxis=dict(autorange="reversed"),
    )
    return fig
