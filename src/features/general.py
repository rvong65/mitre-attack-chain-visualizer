"""
General suspicious features: suspicious parents, elevated user, URL in cmdline, network.
"""
import re

import pandas as pd

# Suspicious parent processes (T1059, T1003, T1547 often chain through these)
_SUSPICIOUS_PARENT = re.compile(
    r"rundll32|regsvr32|certutil|bitsadmin", re.IGNORECASE
)
_URL_PATTERN = re.compile(r"https?://", re.IGNORECASE)


def create_general_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add general suspiciousness flags:
    - is_suspicious_parent: parent_process contains rundll32, regsvr32, certutil, bitsadmin
    - is_elevated: user contains SYSTEM or NT AUTHORITY
    - cmdline_has_url: cmdline contains http:// or https://
    - network_outbound_flag: dest_ip present and non-empty
    """
    if df.empty:
        return df
    df = df.copy()
    parent = df.get("parent_process", pd.Series(dtype=object)).fillna("").astype(str)
    user = df.get("user", pd.Series(dtype=object)).fillna("").astype(str)
    cmd = df.get("cmdline", pd.Series(dtype=object)).fillna("").astype(str)
    dest_ip = df.get("dest_ip", pd.Series(dtype=object)).fillna("").astype(str)

    df["is_suspicious_parent"] = parent.str.contains(
        _SUSPICIOUS_PARENT, regex=True, na=False
    )
    df["is_elevated"] = user.str.contains(
        r"SYSTEM|NT AUTHORITY", regex=True, na=False
    )
    df["cmdline_has_url"] = cmd.str.contains(_URL_PATTERN, regex=True, na=False)
    # dest_ip present and non-empty
    df["network_outbound_flag"] = (dest_ip.str.strip().str.len() > 0) & (
        dest_ip != "nan"
    )

    return df
