"""
Loader for Windows PowerShell operational logs (multi-line key=value records).
"""
import logging
import re
from pathlib import Path
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)

# Record separator: MM/DD/YYYY H:MM:SS AM/PM
_TIMESTAMP_PATTERN = re.compile(
    r"^(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*[AP]M)\s*$", re.IGNORECASE
)
# Key=Value (value is rest of line; may be empty)
_KV_PATTERN = re.compile(r"^([A-Za-z][A-Za-z0-9]*)=(.*)$")
_SCRIPT_BLOCK_ID = re.compile(r"^ScriptBlock ID:\s*(.+)$")
_PATH_PREFIX = re.compile(r"^Path:\s*(.*)$")


def _split_into_records(text: str) -> list[list[str]]:
    """Split file content into records; each record is a list of lines starting with a timestamp line."""
    records = []
    current: list[str] = []
    for line in text.splitlines():
        if _TIMESTAMP_PATTERN.match(line.strip()):
            if current:
                records.append(current)
            current = [line.strip()]
        else:
            if current:
                current.append(line)
    if current:
        records.append(current)
    return records


def _parse_record(lines: list[str]) -> dict[str, Any] | None:
    """Parse one record (first line = timestamp, rest = Key=Value or ScriptBlock ID / Path / content)."""
    if not lines:
        return None
    timestamp_str = lines[0].strip()
    data = {
        "timestamp": timestamp_str,
        "EventCode": None,
        "Message": "",
        "script_content": "",
        "ScriptBlockId": "",
        "Path": "",
    }
    i = 1
    script_lines = []
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        kv = _KV_PATTERN.match(stripped)
        if kv:
            key, value = kv.group(1), kv.group(2)
            if key == "EventCode":
                try:
                    data["EventCode"] = int(value)
                except ValueError:
                    data["EventCode"] = None
            elif key == "Message":
                data["Message"] = value
                # Message may continue on following lines until next Key= or ScriptBlock/Path
                i += 1
                while i < len(lines):
                    next_line = lines[i]
                    if _KV_PATTERN.match(next_line.strip()) or _SCRIPT_BLOCK_ID.match(
                        next_line.strip()
                    ) or next_line.strip().startswith("Path:"):
                        break
                    data["Message"] += "\n" + next_line
                    i += 1
                continue
        elif _SCRIPT_BLOCK_ID.match(stripped):
            data["ScriptBlockId"] = _SCRIPT_BLOCK_ID.match(stripped).group(1).strip()
        elif stripped.startswith("Path:"):
            m = _PATH_PREFIX.match(stripped)
            data["Path"] = (m.group(1).strip() if m else stripped[5:].strip())
            # Remaining lines in this record may be script content (for 4104)
            i += 1
            while i < len(lines):
                script_lines.append(lines[i])
                i += 1
            break
        i += 1
    if script_lines:
        data["script_content"] = "\n".join(script_lines).strip()
    return data


def load_powershell(
    filepath: Path, technique_id: str, source_file: str
) -> pd.DataFrame:
    """
    Load a PowerShell operational log (multi-line records separated by timestamp).
    Returns DataFrame with columns: timestamp, EventCode, Message, script_content,
    ScriptBlockId, Path, technique_id, source_file.
    """
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        logger.warning("Failed to read %s: %s", filepath, e)
        return pd.DataFrame()
    records = _split_into_records(text)
    rows = []
    for idx, rec_lines in enumerate(records):
        try:
            parsed = _parse_record(rec_lines)
            if parsed is not None:
                parsed["technique_id"] = technique_id
                parsed["source_file"] = source_file
                rows.append(parsed)
        except Exception as e:
            logger.warning(
                "PowerShell parse error at %s record %s: %s", filepath, idx + 1, e
            )
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    return df
