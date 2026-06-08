"""
Timeline visualization helpers: timeline-ready DataFrame, technique→color mapping, chains summary.
For use by Streamlit or other viz; no Streamlit dependency here.
"""
import pandas as pd

# Technique/tactic → color for timeline viz (Execution=red, Persistence=purple, Credential Dumping=orange)
TECHNIQUE_COLORS = {
    "T1059.001": "red",      # Execution / PowerShell
    "T1547.001": "purple",   # Persistence / Run keys
    "T1003.001": "orange",   # Credential Dumping LSASS
    "T1003.003": "orange",   # Credential Dumping NTDS
}
DEFAULT_COLOR = "gray"


def _technique_to_color(techniques_str: str) -> str:
    """Map first matching technique to color; else default."""
    if pd.isna(techniques_str) or not str(techniques_str).strip():
        return DEFAULT_COLOR
    for t in str(techniques_str).split(";"):
        t = t.strip()
        if t in TECHNIQUE_COLORS:
            return TECHNIQUE_COLORS[t]
        if t.startswith("T1003."):
            return TECHNIQUE_COLORS.get("T1003.001", "orange")
    return DEFAULT_COLOR


def prepare_timeline_df(df: pd.DataFrame) -> pd.DataFrame:
    """
    Expects df with chain_id, predicted_chain_techniques, chain_confidence, chain_explanation.
    Ensures timeline-ready columns and adds color_code per event (from first technique in chain).
    """
    if df.empty:
        return df
    df = df.copy()
    if "predicted_chain_techniques" not in df.columns:
        df["predicted_chain_techniques"] = ""
    if "chain_confidence" not in df.columns:
        df["chain_confidence"] = 0.0
    if "chain_explanation" not in df.columns:
        df["chain_explanation"] = ""
    df["color_code"] = df["predicted_chain_techniques"].map(_technique_to_color)
    return df


def summarize_chains(df: pd.DataFrame) -> pd.DataFrame:
    """
    Aggregate to one row per chain: chain_id, start_time, end_time, techniques, chain_confidence,
    num_events, chain_explanation.
    """
    if df.empty or "chain_id" not in df.columns:
        return pd.DataFrame(columns=["chain_id", "start_time", "end_time", "techniques", "chain_confidence", "num_events", "chain_explanation"])

    summary = df.groupby("chain_id").agg(
        start_time=("timestamp", "min"),
        end_time=("timestamp", "max"),
        techniques=("predicted_chain_techniques", "first"),
        chain_confidence=("chain_confidence", "first"),
        chain_explanation=("chain_explanation", "first"),
    ).reset_index()
    n_events = df.groupby("chain_id").size().reset_index(name="num_events")
    summary = summary.merge(n_events, on="chain_id")
    return summary
