"""
PowerShell-related features for T1059.001 (Command and Scripting Interpreter: PowerShell).
Flags: encoded commands, -enc/-nop/-w hidden, powershell in process/cmdline, Invoke-*,
Office -> cmd/powershell chains.
"""
import re

import pandas as pd

# -enc, -EncodedCommand, -nop, -w hidden (obfuscation/evasion)
_ENC_FLAGS = re.compile(
    r"-enc|-EncodedCommand|-[eE]nc|-nop|-w\s+hidden", re.IGNORECASE
)
# Invoke-* keywords (common in malicious scripts)
_INVOKE_KEYWORDS = re.compile(
    r"Invoke-(?:Expression|WebRequest|DownloadString|Command|RestMethod)",
    re.IGNORECASE,
)
# Office apps that may spawn PowerShell (T1059.001: Office -> cmd -> powershell)
_OFFICE_PARENTS = re.compile(
    r"winword|excel|powerpnt|outlook", re.IGNORECASE
)
# Child process indicates scripting
_SCRIPT_CHILD = re.compile(r"cmd|powershell", re.IGNORECASE)


def create_powershell_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add PowerShell technique flags for T1059.001:
    - has_enc_flags: -enc, -EncodedCommand, -nop, -w hidden in cmdline
    - has_powershell_process: process_path or cmdline contains powershell
    - has_invoke_keywords: Invoke-Expression, Invoke-WebRequest, etc.
    - is_office_to_powershell: Office parent AND cmd/powershell in process or cmdline
    """
    if df.empty:
        return df
    df = df.copy()
    cmd = df.get("cmdline", pd.Series(dtype=object)).fillna("").astype(str)
    process = df.get("process_path", pd.Series(dtype=object)).fillna("").astype(str)
    parent = df.get("parent_process", pd.Series(dtype=object)).fillna("").astype(str)

    combined = (process + " " + cmd).str.lower()
    df["has_enc_flags"] = cmd.str.contains(_ENC_FLAGS, regex=True, na=False)
    df["has_powershell_process"] = combined.str.contains("powershell", na=False)
    df["has_invoke_keywords"] = cmd.str.contains(_INVOKE_KEYWORDS, regex=True, na=False)
    # Office spawn: parent is Office app and child is cmd/powershell
    office_parent = parent.str.contains(_OFFICE_PARENTS, regex=True, na=False)
    script_child = combined.str.contains(_SCRIPT_CHILD, regex=True, na=False)
    df["is_office_to_powershell"] = office_parent & script_child

    return df
