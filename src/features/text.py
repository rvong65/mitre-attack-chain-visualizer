"""
Text features: cmdline_lower, length, arg count, entropy.
Targets obfuscation and script complexity (e.g. T1059.001).
"""
import math
from collections import Counter

import pandas as pd


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of string (character-level). High = obfuscation."""
    if not s or len(s) < 2:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def create_text_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add text-derived features from cmdline:
    - cmdline_lower: lowercase for case-insensitive matching
    - cmdline_length: character count
    - cmdline_arg_count: whitespace-split token count
    - cmdline_entropy: Shannon entropy (high suggests obfuscation)
    """
    if df.empty:
        return df
    df = df.copy()
    cmd = df.get("cmdline", pd.Series(dtype=object)).fillna("").astype(str)

    df["cmdline_lower"] = cmd.str.lower()
    df["cmdline_length"] = cmd.str.len().fillna(0).astype(int)
    # Arg count: split on whitespace, filter empty
    df["cmdline_arg_count"] = cmd.str.split().str.len().fillna(0).astype(int)
    # Entropy: apply to each string (vectorized via apply for custom function)
    df["cmdline_entropy"] = cmd.apply(_shannon_entropy).fillna(0.0)

    return df
