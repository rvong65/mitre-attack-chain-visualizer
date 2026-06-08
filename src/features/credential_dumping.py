"""
Credential dumping features for T1003.001 (LSASS) and T1003.003 (NTDS).
Flags: lsass access, procdump/minidump/comsvcs.dll/rundll32, handle.exe/taskmgr parents.
"""
import re

import pandas as pd

_LSASS = re.compile(r"lsass", re.IGNORECASE)
_PROCDUMP_MINIDUMP = re.compile(
    r"procdump|minidump|\.dmp", re.IGNORECASE
)
_COMSVCS_RUNDLL32 = re.compile(
    r"comsvcs\.dll|rundll32.*dump|rundll32.*MiniDump",
    re.IGNORECASE,
)
_HANDLE_TASKMGR = re.compile(r"handle\.exe|taskmgr\.exe", re.IGNORECASE)


def create_credential_dumping_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add credential dumping flags for T1003.001 / T1003.003:
    - has_lsass_mention: process_path or cmdline mentions lsass
    - has_procdump_minidump: cmdline or file_path matches procdump|minidump|.dmp
    - has_comsvcs_rundll32: cmdline contains comsvcs.dll or rundll32 with dump args
    - has_handle_taskmgr_parent: parent_process contains handle.exe or taskmgr.exe
    """
    if df.empty:
        return df
    df = df.copy()
    cmd = df.get("cmdline", pd.Series(dtype=object)).fillna("").astype(str)
    process = df.get("process_path", pd.Series(dtype=object)).fillna("").astype(str)
    parent = df.get("parent_process", pd.Series(dtype=object)).fillna("").astype(str)
    file_path = df.get("file_path", pd.Series(dtype=object)).fillna("").astype(str)

    combined = process + " " + cmd
    cmd_or_file = cmd + " " + file_path

    df["has_lsass_mention"] = combined.str.contains(_LSASS, regex=True, na=False)
    df["has_procdump_minidump"] = cmd_or_file.str.contains(
        _PROCDUMP_MINIDUMP, regex=True, na=False
    )
    df["has_comsvcs_rundll32"] = cmd.str.contains(
        _COMSVCS_RUNDLL32, regex=True, na=False
    )
    df["has_handle_taskmgr_parent"] = parent.str.contains(
        _HANDLE_TASKMGR, regex=True, na=False
    )

    return df
