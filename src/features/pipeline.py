"""
Feature engineering pipeline: load, add features, save, EDA, sample output.
"""
import pandas as pd

from ..config import PROCESSED_DIR
from .credential_dumping import create_credential_dumping_features
from .general import create_general_features
from .load import load_events
from .parent_child import create_parent_child_features
from .powershell import create_powershell_features
from .runkey import create_runkey_features
from .text import create_text_features

# New binary flags added by feature modules (for EDA)
_FEATURE_FLAGS = [
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


def run_feature_engineering(prefer_parquet: bool = True) -> pd.DataFrame:
    """
    Load master_events, add all engineered features, save to combined_features.csv.
    Prints EDA and 5 sample rows per technique.
    Returns the enhanced DataFrame.
    """
    df = load_events(prefer_parquet=prefer_parquet)
    if df.empty:
        print("No events to process.")
        return df

    # Apply feature modules in order
    df = create_text_features(df)
    df = create_general_features(df)
    df = create_powershell_features(df)
    df = create_credential_dumping_features(df)
    df = create_runkey_features(df)
    df = create_parent_child_features(df)

    # Save
    out_path = PROCESSED_DIR / "combined_features.csv"
    df.to_csv(out_path, index=False)
    print(f"Saved to {out_path} ({len(df)} rows, {len(df.columns)} columns)")

    # EDA
    _print_eda(df)
    _print_sample_rows(df)

    return df


def _print_eda(df: pd.DataFrame) -> None:
    """EDA: value_counts of flags by technique_id, top cmdline patterns."""
    print("\n--- EDA: Feature flag counts by technique_id ---")
    flags = [c for c in _FEATURE_FLAGS if c in df.columns]
    if flags and "technique_id" in df.columns:
        for flag in flags:
            vc = df.groupby("technique_id")[flag].sum()
            print(f"\n{flag}:")
            print(vc.to_string())

    print("\n--- Top 10 cmdline patterns per technique (truncated to 80 chars) ---")
    if "technique_id" in df.columns and "cmdline" in df.columns:
        cmd = df["cmdline"].fillna("").astype(str).str[:80]
        for tid in df["technique_id"].unique():
            mask = df["technique_id"] == tid
            top = cmd[mask].value_counts().head(10)
            print(f"\n{tid}:")
            for pat, count in top.items():
                print(f"  {count:5d}: {pat[:60]}...")
            if top.empty:
                print("  (none)")

    print("\n--- Correlation note ---")
    numeric_cols = df.select_dtypes(include="number").columns.tolist()
    flag_cols = [c for c in flags if c in df.columns]
    if flag_cols and len(df) > 1000:
        sample = df.sample(n=min(1000, len(df)), random_state=42)
        corr = sample[flag_cols].corr()
        print(
            "Sampled 1000 rows for flag correlations. "
            "Use combined_features.csv for full analysis."
        )


def _print_sample_rows(df: pd.DataFrame) -> None:
    """Print 5 sample rows per technique with new feature columns."""
    print("\n--- Sample rows (5 per technique) ---")
    if "technique_id" not in df.columns:
        return
    feat_cols = [c for c in _FEATURE_FLAGS if c in df.columns]
    feat_cols.extend(
        [c for c in ["cmdline_length", "cmdline_arg_count", "cmdline_entropy"] if c in df.columns]
    )
    key_cols = ["technique_id", "event_type", "process_path"] + feat_cols
    key_cols = [c for c in key_cols if c in df.columns]
    for tid in sorted(df["technique_id"].unique()):
        subset = df[df["technique_id"] == tid].head(5)
        print(f"\n{tid}:")
        print(subset[key_cols].to_string())


if __name__ == "__main__":
    run_feature_engineering()
