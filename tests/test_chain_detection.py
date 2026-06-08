"""
Tests for attack chain detection and timeline helpers.
"""
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parent.parent
PROCESSED = ROOT / "data" / "processed"


def test_build_chains_and_detect_techniques_smoke():
    """Tiny fixture DF: build_chains adds chain_id; detect_chain_techniques returns confidence in 0-100."""
    from src.chain_detection import build_chains, detect_chain_techniques

    # Two events: parent powershell -> child cmd with same parent_process as first's process_path
    base = "2021-03-01 12:00:00"
    df = pd.DataFrame([
        {
            "timestamp": base,
            "process_path": "C:\\Windows\\System32\\powershell.exe",
            "parent_process": "C:\\Windows\\System32\\cmd.exe",
            "cmdline": "powershell -enc x",
            "technique_id": "T1059.001",
            "has_powershell_process": True,
            "has_enc_flags": True,
        },
        {
            "timestamp": "2021-03-01 12:00:15",
            "process_path": "C:\\Windows\\System32\\cmd.exe",
            "parent_process": "C:\\Windows\\System32\\powershell.exe",
            "cmdline": "cmd /c whoami",
            "technique_id": "T1059.001",
            "has_powershell_process": False,
            "has_enc_flags": False,
        },
    ])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df_with_chains, chains_df = build_chains(df)
    assert "chain_id" in df_with_chains.columns
    assert len(chains_df) >= 1
    # One chain of 2 events (parent-child within 30s)
    chain_ids = df_with_chains["chain_id"].unique()
    assert len(chain_ids) >= 1

    # Detect on first chain's events
    indices = chains_df.iloc[0]["event_indices"]
    sub = df_with_chains.iloc[indices]
    pred, conf, expl, gt = detect_chain_techniques(sub)
    assert 0 <= conf <= 100
    assert isinstance(pred, list)
    assert isinstance(expl, str)
    assert isinstance(gt, set)


def test_prepare_timeline_df_and_summarize_chains():
    """prepare_timeline_df adds color_code; summarize_chains returns one row per chain."""
    from src.timeline_viz_helpers import prepare_timeline_df, summarize_chains

    df = pd.DataFrame([
        {"chain_id": 0, "timestamp": "2021-03-01 12:00:00", "predicted_chain_techniques": "T1059.001", "chain_confidence": 50.0, "chain_explanation": "Test"},
        {"chain_id": 0, "timestamp": "2021-03-01 12:01:00", "predicted_chain_techniques": "T1059.001", "chain_confidence": 50.0, "chain_explanation": "Test"},
        {"chain_id": 1, "timestamp": "2021-03-01 13:00:00", "predicted_chain_techniques": "T1547.001", "chain_confidence": 40.0, "chain_explanation": "Persistence"},
    ])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    out = prepare_timeline_df(df)
    assert "color_code" in out.columns
    assert out["color_code"].iloc[0] == "red"
    assert out["color_code"].iloc[2] == "purple"

    summary = summarize_chains(out)
    assert len(summary) == 2
    assert list(summary.columns) == ["chain_id", "start_time", "end_time", "techniques", "chain_confidence", "chain_explanation", "num_events"] or "num_events" in summary.columns


def test_run_chain_detection_integration():
    """If processed CSV exists, run_chain_detection completes and returns DF with chain columns."""
    from src.chain_detection import run_chain_detection

    if not (PROCESSED / "combined_features.csv").exists():
        if not (PROCESSED / "combined_events.csv").exists() and not (PROCESSED / "classified_improved.csv").exists():
            pytest.skip("No processed CSV found")
    df = run_chain_detection()
    assert not df.empty
    assert "chain_id" in df.columns
    assert "predicted_chain_techniques" in df.columns
    assert "chain_confidence" in df.columns
    assert "chain_explanation" in df.columns
    assert "color_code" in df.columns
    assert df["chain_confidence"].min() >= 0
    assert df["chain_confidence"].max() <= 100


def test_run_chain_detection_refined_smoke():
    """If processed CSV exists, run_chain_detection_refined completes and returns DF with refined columns."""
    from src.chain_refine import run_chain_detection_refined

    if not (PROCESSED / "combined_features.csv").exists():
        if not (PROCESSED / "combined_events.csv").exists() and not (PROCESSED / "classified_improved.csv").exists():
            pytest.skip("No processed CSV found")
    df = run_chain_detection_refined()
    assert not df.empty
    assert "chain_id" in df.columns
    assert "chain_techniques" in df.columns
    assert "chain_confidence" in df.columns
    assert "chain_explanation" in df.columns
    assert "technique_color" in df.columns
    assert "hover_text" in df.columns
    assert "is_multi_event_chain" in df.columns
    assert df["chain_confidence"].min() >= 0
    assert df["chain_confidence"].max() <= 100
    assert (PROCESSED / "events_with_chains_refined.csv").exists()
    assert (PROCESSED / "chains_summary_refined.csv").exists()
