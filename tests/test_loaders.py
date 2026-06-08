"""
Tests: load one file per type, assert columns, df.head(5), value_counts on EventID/event_type.
"""
from pathlib import Path

import pytest

# Project root
ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"


def test_load_one_sysmon():
    """Load one Sysmon file (e.g. T1547.001), assert columns, head(5), value_counts."""
    from src.loaders import load_sysmon
    from src.schema import normalize_to_schema

    path = RAW / "T1547.001" / "windows-sysmon.txt"
    if not path.exists():
        pytest.skip("Raw data not found: T1547.001/windows-sysmon.txt")
    df = load_sysmon(path, "T1547.001", "windows-sysmon.txt")
    assert not df.empty
    assert "EventID" in df.columns
    assert "Image" in df.columns
    assert "CommandLine" in df.columns
    print(df.head(5))
    vc = df["EventID"].value_counts()
    assert len(vc) > 0
    print("EventID value_counts:", vc)
    norm = normalize_to_schema(df, "sysmon")
    assert "event_type" in norm.columns
    print("event_type value_counts:", norm["event_type"].value_counts())


def test_load_one_powershell():
    """Load T1059.001 windows-powershell, assert EventCode/Message, head(5), value_counts."""
    from src.loaders import load_powershell
    from src.schema import normalize_to_schema

    path = RAW / "T1059.001" / "windows-powershell.txt"
    if not path.exists():
        pytest.skip("Raw data not found: T1059.001/windows-powershell.txt")
    df = load_powershell(path, "T1059.001", "windows-powershell.txt")
    assert not df.empty
    assert "EventCode" in df.columns
    assert "Message" in df.columns
    print(df.head(5))
    vc = df["EventCode"].value_counts()
    assert len(vc) > 0
    print("EventCode value_counts:", vc)
    norm = normalize_to_schema(df, "powershell")
    assert "event_type" in norm.columns
    print("event_type value_counts:", norm["event_type"].value_counts())


def test_load_one_falcon():
    """Load T1003.001 crowdstrike_falcon, assert event_simpleName, CommandLine, head(5), value_counts."""
    from src.loaders import load_falcon
    from src.schema import normalize_to_schema

    path = RAW / "T1003.001" / "crowdstrike_falcon.txt"
    if not path.exists():
        pytest.skip("Raw data not found: T1003.001/crowdstrike_falcon.txt")
    df = load_falcon(path, "T1003.001", "crowdstrike_falcon.txt")
    assert not df.empty
    assert "event_simpleName" in df.columns
    assert "CommandLine" in df.columns
    print(df.head(5))
    vc = df["event_simpleName"].value_counts()
    assert len(vc) > 0
    print("event_simpleName value_counts:", vc)
    norm = normalize_to_schema(df, "falcon")
    assert "event_type" in norm.columns
    print("event_type value_counts:", norm["event_type"].value_counts())
