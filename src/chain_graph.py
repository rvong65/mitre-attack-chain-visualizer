"""
Per-chain process-tree graph: nodes and edges from parent_process / process_path within one chain.
"""
from __future__ import annotations

from typing import Any

import pandas as pd
import plotly.graph_objects as go

_PLOTLY_TACTIC_COLORS = {
    "TA0002 Execution": "#ff4444",
    "TA0006 Credential Access": "#ff8800",
    "TA0003 Persistence": "#aa44ff",
    "Multi-Tactic": "#00cccc",
    "Unknown": "#888888",
}


def _norm_path(s: Any) -> str:
    if s is None or (isinstance(s, float) and pd.isna(s)):
        return ""
    return str(s).strip().lower().replace("\\", "/")


def _path_trailing(name: str) -> str:
    n = _norm_path(name)
    if not n:
        return ""
    return n.split("/")[-1].strip()


def _parent_matches(parent_val: str, process_path_val: str) -> bool:
    trail = _path_trailing(parent_val)
    if not trail:
        return False
    pp = _norm_path(process_path_val)
    return trail in pp or pp.endswith(trail) or pp == _norm_path(parent_val)


def build_chain_graph(chain_events: pd.DataFrame) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """
    Build nodes and directed edges for one chain's events (sorted by timestamp).
    Returns (nodes, edges) where each node has id, label, hover fields.
    """
    if chain_events.empty:
        return [], []

    df = chain_events.sort_values("timestamp").reset_index(drop=True)
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []

    for idx, row in df.iterrows():
        proc = str(row.get("process_path", "") or "")
        parent = str(row.get("parent_process", "") or "")
        node_id = f"node-{idx}"
        tactic = str(row.get("chain_tactic", "") or "Unknown")
        nodes.append(
            {
                "id": node_id,
                "label": _path_trailing(proc) or (proc[:30] + "..." if len(proc) > 30 else proc) or f"event-{idx}",
                "process_path": proc,
                "parent_process": parent,
                "cmdline": str(row.get("cmdline", "") or "")[:120],
                "timestamp": str(row.get("timestamp", "")),
                "tactic": tactic,
                "techniques": str(row.get("chain_techniques", "") or ""),
            }
        )

        if parent:
            for j in range(idx):
                prev_proc = str(df.iloc[j].get("process_path", "") or "")
                if _parent_matches(parent, prev_proc):
                    edges.append({"source": f"node-{j}", "target": node_id})
                    break

    return nodes, edges


def _layout_tree(nodes: list[dict[str, Any]], edges: list[dict[str, str]]) -> dict[str, tuple[float, float]]:
    """Layered tree layout: x = depth from roots, y = spread within layer."""
    if not nodes:
        return {}

    children: dict[str, list[str]] = {n["id"]: [] for n in nodes}
    in_degree: dict[str, int] = {n["id"]: 0 for n in nodes}
    for e in edges:
        children[e["source"]].append(e["target"])
        in_degree[e["target"]] = in_degree.get(e["target"], 0) + 1

    roots = [nid for nid, deg in in_degree.items() if deg == 0]
    if not roots:
        roots = [nodes[0]["id"]]

    depth: dict[str, int] = {}
    queue = [(r, 0) for r in roots]
    visited: set[str] = set()
    while queue:
        nid, d = queue.pop(0)
        if nid in visited:
            continue
        visited.add(nid)
        depth[nid] = d
        for child in children.get(nid, []):
            queue.append((child, d + 1))

    for n in nodes:
        if n["id"] not in depth:
            depth[n["id"]] = 0

    layers: dict[int, list[str]] = {}
    for nid, d in depth.items():
        layers.setdefault(d, []).append(nid)

    # preserve timestamp order within layer
    node_order = {n["id"]: i for i, n in enumerate(nodes)}
    for d in layers:
        layers[d].sort(key=lambda x: node_order.get(x, 0))

    positions: dict[str, tuple[float, float]] = {}
    for d, nids in layers.items():
        span = max(len(nids) - 1, 1)
        for i, nid in enumerate(nids):
            x = float(d)
            y = float(i - span / 2)
            positions[nid] = (x, y)

    if len(positions) == 1:
        only = list(positions.keys())[0]
        positions[only] = (0.0, 0.0)

    return positions


def plot_chain_graph_figure(
    chain_events: pd.DataFrame,
    chain_id: Any = None,
    title: str | None = None,
) -> go.Figure:
    """Return a Plotly Figure for the process tree of a single chain."""
    nodes, edges = build_chain_graph(chain_events)
    if not nodes:
        fig = go.Figure()
        fig.update_layout(
            title=title or "Chain graph (no events)",
            template="plotly_dark",
            paper_bgcolor="#0e1117",
            plot_bgcolor="#1e1e1e",
        )
        return fig

    positions = _layout_tree(nodes, edges)
    node_by_id = {n["id"]: n for n in nodes}

    edge_x, edge_y = [], []
    for e in edges:
        x0, y0 = positions[e["source"]]
        x1, y1 = positions[e["target"]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        mode="lines",
        line=dict(width=1.5, color="#666666"),
        hoverinfo="none",
        showlegend=False,
    )

    xs, ys, texts, colors, hovers = [], [], [], [], []
    for n in nodes:
        x, y = positions[n["id"]]
        xs.append(x)
        ys.append(y)
        texts.append(n["label"])
        tactic = n.get("tactic") or "Unknown"
        colors.append(_PLOTLY_TACTIC_COLORS.get(tactic, "#888888"))
        hovers.append(
            f"<b>{n['label']}</b><br>"
            f"Path: {n['process_path'][:80]}<br>"
            f"Time: {n['timestamp']}<br>"
            f"Tactic: {tactic}<br>"
            f"Cmd: {n['cmdline']}"
        )

    node_trace = go.Scatter(
        x=xs,
        y=ys,
        mode="markers+text",
        text=texts,
        textposition="top center",
        textfont=dict(size=10, color="#e0e0e0"),
        marker=dict(size=22, color=colors, line=dict(width=1, color="#ffffff")),
        hovertext=hovers,
        hoverinfo="text",
        showlegend=False,
    )

    fig_title = title or f"Process tree — chain {chain_id}"
    fig = go.Figure(data=[edge_trace, node_trace])
    fig.update_layout(
        title=dict(text=fig_title, font=dict(color="#ffffff")),
        template="plotly_dark",
        paper_bgcolor="#0e1117",
        plot_bgcolor="#1e1e1e",
        font=dict(color="#ffffff"),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, title=""),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, title=""),
        height=500,
        margin=dict(l=20, r=20, t=50, b=20),
    )
    return fig
