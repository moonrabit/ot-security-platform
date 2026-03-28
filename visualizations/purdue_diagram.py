"""
Purdue Model diagram with device placement and security status.
"""
import plotly.graph_objects as go
from config import PURDUE_LEVEL_SHORT


LEVEL_COLORS = {
    0: "#2D4A2D",
    1: "#3A3A1E",
    2: "#1E2E3A",
    3: "#2E1E3A",
    4: "#3A2E1E",
    5: "#2E2E2E",
}

STATUS_COLORS = {
    "ok":       "#44DD44",
    "warning":  "#FFAA00",
    "critical": "#FF4444",
    "unknown":  "#888888",
}


def build_purdue_diagram(devices: list[dict], findings: list[dict]) -> go.Figure:
    """
    Build a Purdue model diagram with discovered devices placed per level.

    Args:
        devices: list of device dicts from scanner
        findings: list of finding dicts from scanner
    """
    fig = go.Figure()

    # Background bands per Purdue level
    for level in range(6):
        fig.add_shape(
            type="rect",
            x0=0, x1=10,
            y0=level - 0.45, y1=level + 0.45,
            fillcolor=LEVEL_COLORS.get(level, "#222"),
            line=dict(color="#555", width=1),
            layer="below",
        )
        fig.add_annotation(
            x=0.1, y=level,
            text=f"<b>L{level}</b>: {PURDUE_LEVEL_SHORT.get(level, '')}",
            showarrow=False,
            xanchor="left",
            font=dict(size=11, color="#CCCCCC"),
        )

    # Determine findings per device IP
    critical_ips: set[str] = set()
    warning_ips: set[str] = set()
    for f in findings:
        ip = f.get("dst_ip") or f.get("src_ip", "")
        sev = f.get("severity", "")
        if sev == "CRITICAL":
            critical_ips.add(ip)
        elif sev in ("HIGH", "MEDIUM"):
            warning_ips.add(ip)

    # Group devices by Purdue level
    level_devices: dict[int, list] = {i: [] for i in range(6)}
    for dev in devices:
        lvl = min(5, max(0, int(dev.get("purdue_level", 2))))
        level_devices[lvl].append(dev)

    # Plot devices
    x_vals, y_vals, colors, labels, hovers = [], [], [], [], []

    for level, devs in level_devices.items():
        n = len(devs)
        for i, dev in enumerate(devs):
            ip = dev.get("ip_address", "?")
            protocols = ", ".join(dev.get("protocols", []))
            pkt_count = dev.get("packet_count", 0)
            x = 1.5 + (i / max(n - 1, 1)) * 7.0 if n > 1 else 5.0
            y = level

            if ip in critical_ips:
                color = STATUS_COLORS["critical"]
            elif ip in warning_ips:
                color = STATUS_COLORS["warning"]
            elif dev.get("protocols"):
                color = STATUS_COLORS["ok"]
            else:
                color = STATUS_COLORS["unknown"]

            finding_count = sum(
                1 for f in findings
                if f.get("src_ip") == ip or f.get("dst_ip") == ip
            )

            x_vals.append(x)
            y_vals.append(y)
            colors.append(color)
            labels.append(ip)
            hovers.append(
                f"<b>{ip}</b><br>Nivel Purdue: {level}<br>"
                f"Protocolos: {protocols or 'N/A'}<br>"
                f"Paquetes: {pkt_count}<br>"
                f"Hallazgos: {finding_count}"
            )

    if x_vals:
        fig.add_trace(go.Scatter(
            x=x_vals,
            y=y_vals,
            mode="markers+text",
            marker=dict(
                color=colors,
                size=18,
                symbol="circle",
                line=dict(width=2, color="#FFFFFF"),
            ),
            text=labels,
            textposition="bottom center",
            hovertext=hovers,
            hoverinfo="text",
            name="Dispositivos OT",
            textfont=dict(size=9, color="#EEEEEE"),
        ))
    else:
        # Empty state
        fig.add_annotation(
            x=5, y=2.5,
            text="No se detectaron dispositivos OT en la captura",
            showarrow=False,
            font=dict(size=14, color="#888"),
        )

    # Legend
    for status, color in STATUS_COLORS.items():
        fig.add_trace(go.Scatter(
            x=[None], y=[None],
            mode="markers",
            marker=dict(size=10, color=color, symbol="circle"),
            name={"ok": "Sin hallazgos", "warning": "Hallazgos medios/altos",
                  "critical": "Hallazgos críticos", "unknown": "Desconocido"}[status],
            showlegend=True,
        ))

    fig.update_layout(
        title="Modelo Purdue — Dispositivos OT Detectados",
        xaxis=dict(visible=False, range=[0, 10]),
        yaxis=dict(
            visible=True,
            tickvals=list(range(6)),
            ticktext=[f"L{i}" for i in range(6)],
            range=[-0.6, 5.6],
            gridcolor="#333",
        ),
        paper_bgcolor="#0E0E0E",
        plot_bgcolor="#0E0E0E",
        font=dict(color="#EEEEEE"),
        height=520,
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.15),
        margin=dict(l=50, r=20, t=60, b=80),
    )

    return fig
