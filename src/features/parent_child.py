"""
Parent-child relationship features.
Flags: Office apps spawning children (T1059.001 chain).
"""
import re

import pandas as pd

_OFFICE = re.compile(r"winword|excel|powerpnt", re.IGNORECASE)


def create_parent_child_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add parent-child flags:
    - is_office_spawn: parent_process contains winword|excel|powerpnt
    """
    if df.empty:
        return df
    df = df.copy()
    parent = df.get("parent_process", pd.Series(dtype=object)).fillna("").astype(str)

    df["is_office_spawn"] = parent.str.contains(_OFFICE, regex=True, na=False)

    return df
