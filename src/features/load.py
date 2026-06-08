"""
Load combined events from CSV or Parquet and handle missing values.
"""
from pathlib import Path

import pandas as pd

from ..config import PROCESSED_DIR


def load_events(prefer_parquet: bool = True) -> pd.DataFrame:
    """
    Load master_events from data/processed/.
    Prefers Parquet if available, else CSV.
    Parses timestamp to datetime and fills missing values.
    """
    parquet_path = PROCESSED_DIR / "master_events.parquet"
    csv_path = PROCESSED_DIR / "master_events.csv"

    if prefer_parquet and parquet_path.exists():
        df = pd.read_parquet(parquet_path)
    elif csv_path.exists():
        df = pd.read_csv(csv_path)
    else:
        raise FileNotFoundError(
            f"No master_events file found in {PROCESSED_DIR}. Run pipeline first."
        )

    df = _handle_missing_values(df)
    df = _parse_timestamp(df)
    return df


def _parse_timestamp(df: pd.DataFrame) -> pd.DataFrame:
    """Parse timestamp column to datetime."""
    if "timestamp" not in df.columns or df.empty:
        return df
    df = df.copy()
    ts = df["timestamp"]
    if ts.dtype == "object" or str(ts.dtype).startswith("str"):
        df["timestamp"] = pd.to_datetime(ts, errors="coerce")
    return df


def _handle_missing_values(df: pd.DataFrame) -> pd.DataFrame:
    """
    Fill NaN: strings with '', numerics with 0, bools with False.
    """
    if df.empty:
        return df
    df = df.copy()
    for col in df.columns:
        if col in ("timestamp",):
            continue
        if df[col].dtype == "bool":
            df[col] = df[col].fillna(False)
        elif pd.api.types.is_numeric_dtype(df[col]):
            df[col] = df[col].fillna(0)
        else:
            df[col] = df[col].fillna("").astype(str)
    return df
