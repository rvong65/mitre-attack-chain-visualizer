"""
Loader for CrowdStrike Falcon EDR logs (JSON object per line).
"""
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)

# Fields we extract for normalization
FALCON_FIELDS = [
    "event_simpleName",
    "timestamp",
    "CommandLine",
    "ImageFileName",
    "ParentBaseFileName",
    "ParentImageFileName",
    "TargetFileName",
    "UserSid",
]


def _parse_falcon_line(line: str) -> dict[str, Any] | None:
    """Parse one JSON line; return dict with normalized timestamp (datetime) or None."""
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError as e:
        logger.warning("Falcon JSON decode error: %s", e)
        return None
    event_simple_name = obj.get("event_simpleName", "")
    ts_ms = obj.get("timestamp")
    if ts_ms is not None:
        try:
            ts = datetime.utcfromtimestamp(int(ts_ms) / 1000.0)
        except (ValueError, TypeError, OSError):
            ts = None
    else:
        ts = None
    row = {
        "event_simpleName": event_simple_name,
        "timestamp": ts,
        "CommandLine": obj.get("CommandLine", ""),
        "ImageFileName": obj.get("ImageFileName", ""),
        "ParentBaseFileName": obj.get("ParentBaseFileName", ""),
        "ParentImageFileName": obj.get("ParentImageFileName", ""),
        "TargetFileName": obj.get("TargetFileName", ""),
        "UserSid": obj.get("UserSid", ""),
        "technique_id": "",
        "source_file": "",
    }
    return row


def load_falcon(filepath: Path, technique_id: str, source_file: str) -> pd.DataFrame:
    """
    Load a CrowdStrike Falcon log file (one JSON object per line).
    Returns DataFrame with columns: event_simpleName, timestamp (datetime), CommandLine,
    ImageFileName, ParentBaseFileName, TargetFileName, UserSid, technique_id, source_file.
    """
    rows = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            try:
                parsed = _parse_falcon_line(line)
                if parsed is not None:
                    parsed["technique_id"] = technique_id
                    parsed["source_file"] = source_file
                    rows.append(parsed)
            except Exception as e:
                logger.warning("Falcon parse error at %s line %s: %s", filepath, i, e)
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows)
