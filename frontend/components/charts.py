"""Plotly figures shared by the pages (one consistent visual language)."""
from __future__ import annotations

import math

import networkx as nx
import plotly.graph_objects as go

from components import theme
from components.ui import CATEGORY_COLORS, CATEGORY_LABELS, STATUS_COLORS

ORG_COLORS = theme.Palette("org")


def _t() -> dict:
    return theme.tokens()


def _rgba(hex_color: str, alpha: float) -> str:
    h = hex_color.lstrip("#")
    return f"rgba({int(h[0:2], 16)},{int(h[2:4], 16)},{int(h[4:6], 16)},{alpha:.2f})"


def _layout(fig: go.Figure, height: int = 320, title: str | None = None, legend: bool = True) -> go.Figure:
    t = _t()
    layout = dict(height=height, margin=dict(l=10, r=10, t=40 if title else 10, b=10),
                  font=dict(family="Source Sans Pro, Segoe UI, sans-serif", size=13, color=t["text"]),
                  showlegend=legend, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                  legend=dict(orientation="h", y=-0.15, font=dict(color=t["muted"])),
                  hoverlabel=dict(bgcolor=t["surface"], bordercolor=t["border"], font=dict(color=t["text"])),
                  modebar=dict(bgcolor="rgba(0,0,0,0)", color=t["muted"], activecolor=t["primary"]))
    if title:  # never pass title=None: Plotly 6 renders it as the literal text "undefined"
        layout["title"] = dict(text=title, font=dict(size=15, color=t["text"]))
    fig.update_layout(**layout)
    fig.update_traces(cliponaxis=False, textfont=dict(color=t["text"]), selector=dict(type="bar"))
    for update in (fig.update_xaxes, fig.update_yaxes):
        update(gridcolor=t["grid"], zeroline=False, linecolor=t["border"], tickfont=dict(color=t["muted"]),
               title_font=dict(color=t["muted"]))
    return fig


def style(fig: go.Figure) -> go.Figure:
    """Apply the active theme to a figure built elsewhere (keeps its title, size and data)."""
    t = _t()
    fig.update_layout(font=dict(family="Source Sans Pro, Segoe UI, sans-serif", color=t["text"]),
                      title_font=dict(color=t["text"]), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      legend=dict(font=dict(color=t["muted"])),
                      hoverlabel=dict(bgcolor=t["surface"], bordercolor=t["border"], font=dict(color=t["text"])),
                      modebar=dict(bgcolor="rgba(0,0,0,0)", color=t["muted"], activecolor=t["primary"]))
    for update in (fig.update_xaxes, fig.update_yaxes):
        update(gridcolor=t["grid"], linecolor=t["border"], tickfont=dict(color=t["muted"]),
               title_font=dict(color=t["muted"]))
    return fig


def donut(values: dict, colors: dict, title: str | None = None, labels: dict | None = None) -> go.Figure:
    keys = [k for k, v in values.items() if v]
    fig = go.Figure(go.Pie(labels=[(labels or {}).get(k, k) for k in keys], values=[values[k] for k in keys],
                           hole=0.62, marker=dict(colors=[colors.get(k, _t()["muted"]) for k in keys],
                                                  line=dict(color=_t()["bg"], width=2)),
                           textinfo="value", sort=False, textfont=dict(color=_t()["bg"])))
    fig.add_annotation(text=f"<b>{sum(values.values())}</b>", showarrow=False,
                       font=dict(size=22, color=_t()["text"]))
    return _layout(fig, 300, title)


def status_donut(by_status: dict) -> go.Figure:
    order = ["IMPORTED", "ANALYZED", "PENDING", "VALIDATED", "REJECTED", "DISPUTED", "INCOMPLETE"]
    return donut({k: by_status.get(k, 0) for k in order}, STATUS_COLORS, "Statut des rapports")


def category_bars(by_category: dict) -> go.Figure:
    cats = ["phishing", "ransomware", "malware", "exploitation"]
    fig = go.Figure(go.Bar(x=[CATEGORY_LABELS[c] for c in cats], y=[by_category.get(c, 0) for c in cats],
                           marker_color=[CATEGORY_COLORS[c] for c in cats], text=[by_category.get(c, 0) for c in cats],
                           textposition="outside"))
    return _layout(fig, 300, "Menaces détectées (classification ML)", legend=False)


def reputation_bars(orgs: list[dict], onchain: dict | None = None) -> go.Figure:
    fig = go.Figure()
    fig.add_bar(name="Réputation analytique (off-chain)", x=[f"Org {o['code']}" for o in orgs],
                y=[o["reputation"] for o in orgs], marker_color=[ORG_COLORS.get(o["code"], _t()["muted"]) for o in orgs],
                text=[f"{o['reputation']:.1f}" for o in orgs], textposition="outside")
    if onchain:
        fig.add_bar(name="Réputation protocolaire (on-chain)", x=[f"Org {o['code']}" for o in orgs],
                    y=[onchain.get(o["code"]) for o in orgs], marker_color=_t()["neutral_bar"],
                    text=[f"{onchain.get(o['code'], 0):.1f}" if onchain.get(o["code"]) is not None else "" for o in orgs],
                    textposition="outside")
    fig.add_hline(y=50, line_dash="dot", line_color=_t()["muted"], annotation_text="neutre",
                  annotation_position="bottom right", annotation_font=dict(size=10, color=_t()["muted"]))
    fig.update_yaxes(range=[0, 108])
    return _layout(fig, 320, "Réputation des organisations")


def bar_h(labels: list[str], values: list[float], color: str | None = None, title: str | None = None,
          height: int = 300, fmt: str = "{:.2f}") -> go.Figure:
    """Horizontal bars; `color` None -> theme primary (champagne)."""
    fig = go.Figure(go.Bar(x=values, y=labels, orientation="h", marker_color=color or _t()["primary"],
                           text=[fmt.format(v) for v in values], textposition="outside"))
    fig.update_yaxes(autorange="reversed")
    if values:
        fig.update_xaxes(range=[0, max(values) * 1.25 if max(values) > 0 else 1])
    return _layout(fig, height, title, legend=False)


def probabilities(probs: dict, predicted: str) -> go.Figure:
    cats = ["phishing", "ransomware", "malware", "exploitation"]
    fig = go.Figure(go.Bar(x=[probs.get(c, 0) for c in cats], y=[CATEGORY_LABELS[c] for c in cats], orientation="h",
                           marker_color=[CATEGORY_COLORS[c] if c == predicted else _t()["neutral_bar"] for c in cats],
                           text=[f"{probs.get(c, 0):.1%}" for c in cats], textposition="outside"))
    fig.update_xaxes(range=[0, 1.1], tickformat=".0%")
    fig.update_yaxes(autorange="reversed")
    return _layout(fig, 230, "Probabilités par classe", legend=False)


def gauge(score: float, final: bool) -> go.Figure:
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=score, number=dict(suffix=" / 100", font=dict(size=34, color=_t()["text"])),
        title=dict(text="Score de fiabilité " + ("(final)" if final else "(provisoire)"),
                   font=dict(size=15, color=_t()["text"])),
        gauge=dict(axis=dict(range=[0, 100], tickcolor=_t()["muted"], tickfont=dict(color=_t()["muted"])),
                   bar=dict(color=_t()["primary"], thickness=0.3), bgcolor="rgba(0,0,0,0)",
                   bordercolor=_t()["border"],
                   steps=[dict(range=[0, 45], color=_t()["gauge_steps"][0]),
                          dict(range=[45, 70], color=_t()["gauge_steps"][1]),
                          dict(range=[70, 100], color=_t()["gauge_steps"][2])])))
    return _layout(fig, 260)


def contributions(details: dict) -> go.Figure:
    c = details["contributions"]
    w = details["weights"]
    fig = go.Figure(go.Waterfall(
        x=[f"R × {w['R']:.2f}", f"Q × {w['Q']:.2f}", f"V × {w['V']:.2f}", "Score S"],
        measure=["relative", "relative", "relative", "total"], y=[c["R"], c["Q"], c["V"], 0],
        text=[f"{c['R']:.1f}", f"{c['Q']:.1f}", f"{c['V']:.1f}", f"{c['R'] + c['Q'] + c['V']:.1f}"],
        textposition="outside", textfont=dict(color=_t()["text"]),
        connector=dict(line=dict(color=_t()["muted"])),
        increasing=dict(marker=dict(color=_t()["primary"])),
        totals=dict(marker=dict(color=_t()["primary_strong"]))))
    fig.update_yaxes(range=[0, 110])
    return _layout(fig, 300, "Contribution de chaque composante", legend=False)


def reputation_history(series: dict[str, list[dict]]) -> go.Figure:
    fig = go.Figure()
    for code, events in series.items():
        if not events:
            continue
        ev = sorted(events, key=lambda e: e["at"])
        xs = [ev[0]["at"]] + [e["at"] for e in ev]
        ys = [ev[0]["old"]] + [e["new"] for e in ev]
        fig.add_scatter(x=list(range(len(xs))), y=ys, mode="lines+markers", name=f"Org {code}",
                        line=dict(color=ORG_COLORS.get(code), width=3), hovertext=["départ"] + [e["explanation"] for e in ev])
    fig.add_hline(y=50, line_dash="dot", line_color=_t()["muted"])
    fig.update_xaxes(title="Événements de réputation (ordre chronologique)")
    fig.update_yaxes(range=[0, 100], title="Réputation")
    return _layout(fig, 340, "Évolution de la réputation")


def correlation_graph(nodes: list[dict], edges: list[dict], highlight: str | None = None) -> go.Figure:
    g = nx.Graph()
    for n in nodes:
        g.add_node(n["id"], **n)
    for e in edges:
        g.add_edge(e["source"], e["target"], weight=e["score"])
    connected = [n for n in g.nodes if g.degree(n) > 0]
    sub = g.subgraph(connected) if connected else g
    if len(sub) == 0:
        return _layout(go.Figure(), 420)
    pos = nx.spring_layout(sub, seed=7, k=1.6 / math.sqrt(max(1, len(sub))), weight="weight")
    fig = go.Figure()
    for u, v, d in sub.edges(data=True):
        w = d["weight"]
        fig.add_scatter(x=[pos[u][0], pos[v][0]], y=[pos[u][1], pos[v][1]], mode="lines", hoverinfo="skip",
                        line=dict(width=1 + 7 * w, color=_rgba(_t()["primary"], 0.25 + 0.6 * w)), showlegend=False)
        fig.add_scatter(x=[(pos[u][0] + pos[v][0]) / 2], y=[(pos[u][1] + pos[v][1]) / 2], mode="markers",
                        marker=dict(size=10, color="rgba(0,0,0,0)"), showlegend=False,
                        hovertext=f"{u} ↔ {v}<br>score {w:.2f}", hoverinfo="text")
    for cat, color in CATEGORY_COLORS.items():
        ns = [n for n in sub.nodes if sub.nodes[n].get("category") == cat]
        if not ns:
            continue
        fig.add_scatter(
            x=[pos[n][0] for n in ns], y=[pos[n][1] for n in ns], mode="markers+text", name=CATEGORY_LABELS[cat],
            text=[n for n in ns], textposition="top center", textfont=dict(size=10, color=_t()["text"]),
            marker=dict(size=[30 if n == highlight else 20 for n in ns], color=color,
                        line=dict(color=[STATUS_COLORS.get(sub.nodes[n].get("status"), _t()["bg"]) for n in ns], width=3)),
            hovertext=[f"<b>{n}</b><br>{sub.nodes[n].get('title', '')[:60]}<br>{sub.nodes[n].get('status')} · "
                       f"Org {sub.nodes[n].get('submitter')}" for n in ns], hoverinfo="text")
    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    return _layout(fig, 520, None)
