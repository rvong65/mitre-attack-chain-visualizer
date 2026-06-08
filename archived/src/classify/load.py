"""
Load combined_features CSV or Parquet for classification.
"""
from pathlib import Path

import pandas as pd

from ..config import PROCESSED_DIR


def load_features(prefer_parquet: bool = True) -> pd.DataFrame:
    """
    Load combined_features from data/processed/.
    Prefers Parquet if available, else CSV.
    """
    parquet_path = PROCESSED_DIR / "combined_features.parquet"
    csv_path = PROCESSED_DIR / "combined_features.csv"

    if prefer_parquet and parquet_path.exists():
        df = pd.read_parquet(parquet_path)
    elif csv_path.exists():
        df = pd.read_csv(csv_path)
    else:
        raise FileNotFoundError(
            f"No combined_features file found in {PROCESSED_DIR}. Run feature engineering first."
        )

    return df
