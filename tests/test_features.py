"""
Tests for feature engineering pipeline.
"""
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PROCESSED = ROOT / "data" / "processed"


def test_run_feature_engineering_returns_dataframe():
    """run_feature_engineering returns non-empty DataFrame when data exists."""
    from src.features import run_feature_engineering

    if not (PROCESSED / "master_events.csv").exists():
        pytest.skip("master_events.csv not found; run pipeline first")
    df = run_feature_engineering(prefer_parquet=False)
    assert not df.empty


def test_feature_columns_exist():
    """Expected feature columns are present after run."""
    from src.features.load import load_events
    from src.features.credential_dumping import create_credential_dumping_features
    from src.features.general import create_general_features
    from src.features.parent_child import create_parent_child_features
    from src.features.powershell import create_powershell_features
    from src.features.runkey import create_runkey_features
    from src.features.text import create_text_features

    if not (PROCESSED / "master_events.csv").exists():
        pytest.skip("master_events.csv not found")
    df = load_events(prefer_parquet=False)
    df = create_text_features(df)
    df = create_general_features(df)
    df = create_powershell_features(df)
    df = create_credential_dumping_features(df)
    df = create_runkey_features(df)
    df = create_parent_child_features(df)

    expected = [
        "cmdline_lower",
        "cmdline_length",
        "cmdline_arg_count",
        "cmdline_entropy",
        "is_suspicious_parent",
        "is_elevated",
        "cmdline_has_url",
        "network_outbound_flag",
        "has_enc_flags",
        "has_powershell_process",
        "has_invoke_keywords",
        "is_office_to_powershell",
        "has_lsass_mention",
        "has_procdump_minidump",
        "has_comsvcs_rundll32",
        "has_handle_taskmgr_parent",
        "has_run_registry",
        "has_reg_exe",
        "has_set_itemproperty",
        "is_office_spawn",
    ]
    for col in expected:
        assert col in df.columns, f"Missing column: {col}"


def test_technique_id_preserved():
    """technique_id values are preserved through feature engineering."""
    from src.features import run_feature_engineering

    if not (PROCESSED / "master_events.csv").exists():
        pytest.skip("master_events.csv not found")
    df = run_feature_engineering(prefer_parquet=False)
    assert "technique_id" in df.columns
    assert set(df["technique_id"].unique()).issubset(
        {"T1059.001", "T1003.001", "T1003.003", "T1547.001"}
    )


def test_no_nan_in_boolean_flags():
    """Boolean feature flags have no unexpected NaN after processing."""
    from src.features import run_feature_engineering

    if not (PROCESSED / "master_events.csv").exists():
        pytest.skip("master_events.csv not found")
    df = run_feature_engineering(prefer_parquet=False)
    flag_cols = [
        "has_base64",
        "is_persistence_attempt",
        "has_enc_flags",
        "has_powershell_process",
        "has_invoke_keywords",
        "is_office_to_powershell",
        "has_lsass_mention",
        "has_procdump_minidump",
        "has_comsvcs_rundll32",
        "has_handle_taskmgr_parent",
        "has_run_registry",
        "has_reg_exe",
        "has_set_itemproperty",
        "is_suspicious_parent",
        "is_elevated",
        "cmdline_has_url",
        "network_outbound_flag",
        "is_office_spawn",
    ]
    for col in flag_cols:
        if col in df.columns:
            assert df[col].isna().sum() == 0, f"Unexpected NaN in {col}"
