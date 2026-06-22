"""Tests for per-chain process-tree graph."""
import pandas as pd

from src.chain_graph import build_chain_graph, plot_chain_graph_figure


def _sample_chain_events():
    return pd.DataFrame(
        [
            {
                "timestamp": "2021-03-01 12:00:00",
                "process_path": r"C:\Windows\System32\cmd.exe",
                "parent_process": r"C:\Windows\explorer.exe",
                "cmdline": "cmd.exe",
                "chain_tactic": "TA0002 Execution",
                "chain_techniques": "T1059.001",
            },
            {
                "timestamp": "2021-03-01 12:00:05",
                "process_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "parent_process": r"C:\Windows\System32\cmd.exe",
                "cmdline": "powershell -enc ...",
                "chain_tactic": "TA0002 Execution",
                "chain_techniques": "T1059.001",
            },
        ]
    )


def test_build_chain_graph_nodes_and_edges():
    nodes, edges = build_chain_graph(_sample_chain_events())
    assert len(nodes) == 2
    assert len(edges) == 1
    assert edges[0]["source"] == "node-0"
    assert edges[0]["target"] == "node-1"


def test_build_chain_graph_empty():
    nodes, edges = build_chain_graph(pd.DataFrame())
    assert nodes == []
    assert edges == []


def test_plot_chain_graph_figure():
    fig = plot_chain_graph_figure(_sample_chain_events(), chain_id=1)
    assert len(fig.data) == 2
    assert fig.layout.height == 500
