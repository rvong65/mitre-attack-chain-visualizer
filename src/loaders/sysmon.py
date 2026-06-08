"""
Loader for Windows Sysmon logs (XML event per line).
"""
import logging
import re
from pathlib import Path
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)

# One <Event> per line; extract EventID, TimeCreated, and <Data Name='...'>...</Data>
_RE_EVENT_ID = re.compile(r"<EventID>(\d+)</EventID>")
_RE_TIME_CREATED = re.compile(r"TimeCreated SystemTime='([^']+)'")
_RE_DATA = re.compile(r"<Data Name='([^']+)'>([\s\S]*?)</Data>", re.DOTALL)


def _parse_sysmon_line(line: str) -> dict[str, Any] | None:
    """Parse one Sysmon XML event line. Returns dict of fields or None if not parseable."""
    line = line.strip()
    if not line.startswith("<Event"):
        return None
    event_id_match = _RE_EVENT_ID.search(line)
    if not event_id_match:
        logger.warning("Sysmon line missing EventID: %s", line[:200])
        return None
    event_id = int(event_id_match.group(1))
    time_created_match = _RE_TIME_CREATED.search(line)
    utc_time = time_created_match.group(1) if time_created_match else ""
    data = {}
    for name, value in _RE_DATA.findall(line):
        data[name] = value.strip() if value else ""
    row = {
        "EventID": event_id,
        "TimeCreated": utc_time,
        "UtcTime": data.get("UtcTime", "") or utc_time,
        "Image": data.get("Image", ""),
        "CommandLine": data.get("CommandLine", ""),
        "ParentImage": data.get("ParentImage", ""),
        "ProcessGuid": data.get("ProcessGuid", ""),
        "ParentProcessGuid": data.get("ParentProcessGuid", ""),
        "TargetFilename": data.get("TargetFilename", ""),
        "User": data.get("User", ""),
        "technique_id": "",
        "source_file": "",
    }
    # EventID 13: Registry value set
    if event_id == 13:
        row["TargetObject"] = data.get("TargetObject", "")
        row["Details"] = data.get("Details", "")
    # EventID 3: network; Sysmon may use DestinationIp or DestIp
    row["DestinationIp"] = data.get("DestinationIp", "") or data.get("DestIp", "")
    return row


def load_sysmon(filepath: Path, technique_id: str, source_file: str) -> pd.DataFrame:
    """
    Load a Sysmon log file (XML one event per line).
    Returns DataFrame with columns: EventID, UtcTime, Image, CommandLine, ParentImage,
    TargetFilename, User, technique_id, source_file; for EventID 13 also TargetObject, Details.
    """
    rows = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            try:
                parsed = _parse_sysmon_line(line)
                if parsed is not None:
                    parsed["technique_id"] = technique_id
                    parsed["source_file"] = source_file
                    rows.append(parsed)
            except Exception as e:
                logger.warning("Sysmon parse error at %s line %s: %s", filepath, i, e)
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    return df
