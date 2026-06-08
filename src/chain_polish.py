"""
Pre-UI polish: filter refined chains (min confidence, exclude benign-root-only),
add tactic mapping for UI coloring, build and save polished summary and events.
"""
from pathlib import Path

import pandas as pd

from .config import PROCESSED_DIR

# Tactic labels and colors for UI
TACTIC_COLORS = {
    "TA0002 Execution": "red",
    "TA0006 Credential Access": "orange",
    "TA0003 Persistence": "purple",
    "Multi-Tactic": "cyan",
    "Unknown": "gray",
}


def load_refined_data(
    events_path: Path | None = None,
    summary_path: Path | None = None,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Load events_with_chains_refined.csv and chains_summary_refined.csv.
    Merge chain_benign_root_only from summary onto events. Return (events_df, summary_df).
    """
    events_path = events_path or PROCESSED_DIR / "events_with_chains_refined.csv"
    summary_path = summary_path or PROCESSED_DIR / "chains_summary_refined.csv"
    if not events_path.exists():
        raise FileNotFoundError(f"Refined events not found: {events_path}")
    if not summary_path.exists():
        raise FileNotFoundError(f"Refined summary not found: {summary_path}")

    events_df = pd.read_csv(events_path)
    summary_df = pd.read_csv(summary_path)

    if "timestamp" in events_df.columns:
        events_df["timestamp"] = pd.to_datetime(events_df["timestamp"], errors="coerce")

    if "chain_benign_root_only" in summary_df.columns:
        benign_map = summary_df.set_index("chain_id")["chain_benign_root_only"]
        events_df["chain_benign_root_only"] = events_df["chain_id"].map(benign_map).fillna(False)
    else:
        events_df["chain_benign_root_only"] = False

    return events_df, summary_df


def apply_polish_filters(
    events_df: pd.DataFrame,
    summary_df: pd.DataFrame,
    min_confidence: int = 40,
) -> pd.DataFrame:
    """
    Keep only chains with chain_confidence >= min_confidence and not chain_benign_root_only.
    Return filtered events DataFrame.
    """
    if "chain_benign_root_only" not in events_df.columns and "chain_benign_root_only" in summary_df.columns:
        benign_map = summary_df.set_index("chain_id")["chain_benign_root_only"]
        events_df = events_df.copy()
        events_df["chain_benign_root_only"] = events_df["chain_id"].map(benign_map).fillna(False)
    elif "chain_benign_root_only" not in events_df.columns:
        events_df = events_df.copy()
        events_df["chain_benign_root_only"] = False

    keep_conf = events_df["chain_confidence"] >= min_confidence
    drop_benign = ~events_df["chain_benign_root_only"]
    return events_df[keep_conf & drop_benign].copy()


def add_tactic_mapping(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add chain_tactic and tactic_color from chain_techniques.
    TA0002 Execution (T1059.001), TA0006 Credential Access (T1003), TA0003 Persistence (T1547.001),
    Multi-Tactic if more than one, else Unknown.
    """
    df = df.copy()
    tech_col = df.get("chain_techniques", pd.Series(dtype=str)).fillna("").astype(str)

    def _tactic(tech_str: str) -> str:
        s = tech_str.upper()
        has_exec = "T1059.001" in s
        has_cred = "T1003" in s
        has_persist = "T1547.001" in s
        count = sum([has_exec, has_cred, has_persist])
        if count >= 2:
            return "Multi-Tactic"
        if has_exec:
            return "TA0002 Execution"
        if has_cred:
            return "TA0006 Credential Access"
        if has_persist:
            return "TA0003 Persistence"
        return "Unknown"

    df["chain_tactic"] = tech_col.map(_tactic)
    df["tactic_color"] = df["chain_tactic"].map(lambda t: TACTIC_COLORS.get(t, "gray"))
    return df


def build_chains_summary_polished(events_df: pd.DataFrame) -> pd.DataFrame:
    """
    Group by chain_id; columns: Chain ID, Start Time, End Time, Duration, Num Events,
    Techniques (comma-joined), Tactic, Confidence Score, Explanation.
    Sort descending by Confidence Score, then ascending by Start Time.
    """
    if events_df.empty or "chain_id" not in events_df.columns:
        return pd.DataFrame(
            columns=[
                "Chain ID", "Start Time", "End Time", "Duration", "Num Events",
                "Techniques", "Tactic", "Confidence Score", "Explanation",
            ]
        )

    g = events_df.groupby("chain_id")
    summary = g.agg(
        **{
            "Start Time": ("timestamp", "min"),
            "End Time": ("timestamp", "max"),
            "Techniques": ("chain_techniques", "first"),
            "Tactic": ("chain_tactic", "first"),
            "Confidence Score": ("chain_confidence", "first"),
            "Explanation": ("chain_explanation", "first"),
        },
    ).reset_index()
    summary = summary.rename(columns={"chain_id": "Chain ID"})
    summary["Duration"] = (summary["End Time"] - summary["Start Time"]).dt.total_seconds()
    summary["Num Events"] = g.size().values
    summary["Techniques"] = summary["Techniques"].fillna("").astype(str).str.replace(";", ", ", regex=False)

    summary = summary.sort_values(
        by=["Confidence Score", "Start Time"],
        ascending=[False, True],
    ).reset_index(drop=True)
    return summary


def run_chain_polish(
    events_path: Path | None = None,
    summary_path: Path | None = None,
    min_confidence: int = 40,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Load refined data -> apply filters -> add tactic mapping -> build summary -> save polished CSVs.
    Return (events_polished, summary_polished).
    """
    events_df, summary_df = load_refined_data(events_path, summary_path)
    events_filtered = apply_polish_filters(events_df, summary_df, min_confidence=min_confidence)
    events_polished = add_tactic_mapping(events_filtered)
    summary_polished = build_chains_summary_polished(events_polished)

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    out_events = PROCESSED_DIR / "events_with_chains_polished.csv"
    out_summary = PROCESSED_DIR / "chains_summary_polished.csv"
    # Drop benign column from saved events to keep schema clean
    save_events = events_polished.drop(columns=["chain_benign_root_only"], errors="ignore")
    save_events.to_csv(out_events, index=False)
    summary_polished.to_csv(out_summary, index=False)
    print(f"Saved {out_events} ({len(save_events)} rows) and {out_summary} ({len(summary_polished)} chains).")
    return events_polished, summary_polished


if __name__ == "__main__":
    run_chain_polish()
