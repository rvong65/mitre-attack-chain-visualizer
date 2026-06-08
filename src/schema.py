"""
Common schema and event_type mappings for normalized log data.
"""
from datetime import datetime
from typing import Literal

import pandas as pd

# Normalized output columns (all loaders map to this).
# ProcessGuid/ParentProcessGuid optional (Sysmon only; empty for others) for process tree building.
NORMALIZED_COLUMNS = [
    "timestamp",
    "event_type",
    "process_path",
    "cmdline",
    "parent_process",
    "user",
    "dest_ip",
    "registry_key",
    "file_path",
    "technique_id",
    "source_file",
    "ProcessGuid",
    "ParentProcessGuid",
]

# Sysmon EventID -> event_type
SYSMON_EVENT_TYPE = {
    1: "Process Creation",
    3: "Network Connection",
    10: "Process Access",
    13: "Registry Value Set",
    23: "File Delete",
}

# Falcon event_simpleName -> event_type (subset we care about; others can map to generic or name)
FALCON_EVENT_TYPE = {
    "ProcessRollup2": "Process Creation",
    "SyntheticProcessRollup2": "Process Creation",
    "FileDeleteInfo": "File Delete",
    "DmpFileWritten": "Dump File Written",
    "ProcessHandleOpDetectInfo": "Process Handle",
}

# PowerShell EventCode -> event_type
POWERSHELL_EVENT_TYPE = {
    4104: "PowerShell Script Block",
    4105: "PowerShell Invocation",
    4106: "PowerShell Invocation",
}

SourceType = Literal["sysmon", "powershell", "falcon"]


def _parse_sysmon_time(s: str) -> datetime | None:
    """Parse Sysmon UtcTime e.g. '2021-03-01 22:52:47.379' or TimeCreated '2021-03-01T22:52:47.382490200Z'."""
    if not s or pd.isna(s):
        return None
    s = str(s).strip()
    # TimeCreated ISO format
    if "T" in s and "Z" in s:
        s = s.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(s.replace("+00:00", ""))
        except ValueError:
            pass
    # UtcTime space-separated
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s[:26] if len(s) > 26 else s, fmt)
        except ValueError:
            continue
    return None


def _parse_powershell_time(s: str) -> datetime | None:
    """Parse PowerShell timestamp e.g. '03/01/2021 10:52:57 PM'."""
    if not s or pd.isna(s):
        return None
    s = str(s).strip()
    try:
        return datetime.strptime(s, "%m/%d/%Y %I:%M:%S %p")
    except ValueError:
        return None


def normalize_to_schema(
    raw_df: pd.DataFrame, source_type: SourceType
) -> pd.DataFrame:
    """
    Map raw loader output to common schema. Returns DataFrame with NORMALIZED_COLUMNS.
    """
    if raw_df.empty:
        return pd.DataFrame(columns=NORMALIZED_COLUMNS)

    out = pd.DataFrame(index=raw_df.index)
    out["technique_id"] = raw_df.get("technique_id", "")
    out["source_file"] = raw_df.get("source_file", "")

    if source_type == "sysmon":
        out["event_type"] = raw_df["EventID"].map(
            lambda x: SYSMON_EVENT_TYPE.get(x, f"Sysmon_{x}")
        )
        out["timestamp"] = raw_df.get("UtcTime", raw_df.get("TimeCreated", "")).map(
            _parse_sysmon_time
        )
        out["process_path"] = raw_df.get("Image", "")
        out["cmdline"] = raw_df.get("CommandLine", "")
        out["parent_process"] = raw_df.get("ParentImage", "")
        out["user"] = raw_df.get("User", "")
        out["file_path"] = raw_df.get("TargetFilename", "")
        # EID 13: TargetObject is key path, Details is value
        out["registry_key"] = (
            raw_df.get("TargetObject", pd.Series(dtype=object)).fillna("").astype(str)
            + " "
            + raw_df.get("Details", pd.Series(dtype=object)).fillna("").astype(str)
        ).str.strip()
        out["dest_ip"] = raw_df.get("DestinationIp", "")
        out["ProcessGuid"] = raw_df.get("ProcessGuid", pd.Series(dtype=object)).fillna("").astype(str)
        out["ParentProcessGuid"] = raw_df.get("ParentProcessGuid", pd.Series(dtype=object)).fillna("").astype(str)
    elif source_type == "falcon":
        out["event_type"] = raw_df["event_simpleName"].map(
            lambda x: FALCON_EVENT_TYPE.get(x, x or "Unknown")
        )
        out["timestamp"] = raw_df.get("timestamp")  # already datetime
        out["process_path"] = raw_df.get("ImageFileName", "")
        out["cmdline"] = raw_df.get("CommandLine", "")
        out["parent_process"] = raw_df.get(
            "ParentBaseFileName", pd.Series(dtype=object)
        ).fillna(raw_df.get("ParentImageFileName", ""))
        out["user"] = raw_df.get("UserSid", "")
        out["file_path"] = raw_df.get("TargetFileName", "")
        out["registry_key"] = ""
        out["dest_ip"] = ""
        out["ProcessGuid"] = ""
        out["ParentProcessGuid"] = ""
    else:  # powershell
        out["event_type"] = raw_df["EventCode"].map(
            lambda x: POWERSHELL_EVENT_TYPE.get(x, f"PowerShell_{x}")
            if x is not None
            else "Unknown"
        )
        out["timestamp"] = raw_df.get("timestamp", "").map(_parse_powershell_time)
        out["process_path"] = "powershell"
        # Prefer script content for 4104, else Message
        script = raw_df.get("script_content", pd.Series(dtype=object)).fillna("")
        msg = raw_df.get("Message", pd.Series(dtype=object)).fillna("")
        out["cmdline"] = script.where(script.astype(str).str.strip().str.len() > 0, msg)
        out["parent_process"] = ""
        out["user"] = ""
        out["file_path"] = raw_df.get("Path", "")
        out["registry_key"] = ""
        out["dest_ip"] = ""
        out["ProcessGuid"] = ""
        out["ParentProcessGuid"] = ""

    out = out.reindex(columns=NORMALIZED_COLUMNS)
    return out
