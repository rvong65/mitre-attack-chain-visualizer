"""
Registry Run Keys / Startup features for T1547.001.
Flags: registry_key Run/RunOnce/CurrentVersion, reg.exe, Set-ItemProperty.
"""
import re

import pandas as pd

_RUN_REGISTRY = re.compile(
    r"\\Run\\|\\RunOnce\\|CurrentVersion\\Run", re.IGNORECASE
)
_REG_EXE = re.compile(r"reg\.exe", re.IGNORECASE)
# Set-ItemProperty used with Run/RunOnce/Startup (PowerShell persistence)
_SET_ITEMPROPERTY = re.compile(
    r"Set-ItemProperty.*(?:Run|RunOnce|Startup)|" r"(?:Run|RunOnce|Startup).*Set-ItemProperty",
    re.IGNORECASE | re.DOTALL,
)


def create_runkey_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add T1547.001 Run Key / Startup flags:
    - has_run_registry: registry_key contains Run, RunOnce, CurrentVersion\\Run
    - has_reg_exe: process_path or cmdline contains reg.exe
    - has_set_itemproperty: cmdline contains Set-ItemProperty with Run/Startup context
    (is_persistence_attempt already exists from pipeline)
    """
    if df.empty:
        return df
    df = df.copy()
    reg = df.get("registry_key", pd.Series(dtype=object)).fillna("").astype(str)
    cmd = df.get("cmdline", pd.Series(dtype=object)).fillna("").astype(str)
    process = df.get("process_path", pd.Series(dtype=object)).fillna("").astype(str)

    combined = process + " " + cmd

    df["has_run_registry"] = reg.str.contains(
        _RUN_REGISTRY, regex=True, na=False
    )
    df["has_reg_exe"] = combined.str.contains(_REG_EXE, regex=True, na=False)
    df["has_set_itemproperty"] = cmd.str.contains(
        _SET_ITEMPROPERTY, regex=True, na=False
    )

    return df
