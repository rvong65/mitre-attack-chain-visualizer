"""
Pipeline: discover raw logs, load, normalize, add derived columns, combine, save.
"""
import logging
import re
from pathlib import Path

import pandas as pd

from .config import FILE_PATTERNS, PROCESSED_DIR, RAW_DIR, TECHNIQUE_FOLDERS
from .loaders import load_falcon, load_powershell, load_sysmon
from .schema import SourceType, normalize_to_schema

logger = logging.getLogger(__name__)

# Derived column: base64-like in cmdline (encoded commands)
_BASE64_PATTERN = re.compile(
    r"(?:-enc|-EncodedCommand|-[eE]nc)\s+|"
    r"[A-Za-z0-9+/]{40,}=*"
)
# Persistence: Run keys, startup folder, reg add ... Run
_PERSISTENCE_PATTERN = re.compile(
    r"\\\\Run\\\\|\\\\RunOnce\\\\|CurrentVersion\\\\Run|"
    r"startup\s*folder|"
    r"reg\s+add\s+.*(?:HKLM|HKCU).*\\\\Run",
    re.IGNORECASE,
)


def _add_derived_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Add has_base64 and is_persistence_attempt from cmdline and registry_key."""
    if df.empty:
        df["has_base64"] = pd.Series(dtype=bool)
        df["is_persistence_attempt"] = pd.Series(dtype=bool)
        return df
    cmd = df.get("cmdline", pd.Series(dtype=object)).fillna("").astype(str)
    reg = df.get("registry_key", pd.Series(dtype=object)).fillna("").astype(str)
    df = df.copy()
    df["has_base64"] = cmd.str.contains(_BASE64_PATTERN, regex=True, na=False)
    df["is_persistence_attempt"] = (
        reg.str.contains(_PERSISTENCE_PATTERN, regex=True, na=False)
        | cmd.str.contains(_PERSISTENCE_PATTERN, regex=True, na=False)
    )
    return df


def _discover_files() -> list[tuple[str, Path, SourceType]]:
    """Yield (technique_id, filepath, source_type) for each known log file."""
    result = []
    for technique_id in TECHNIQUE_FOLDERS:
        folder = RAW_DIR / technique_id
        if not folder.is_dir():
            continue
        for name, pattern in FILE_PATTERNS.items():
            for path in sorted(folder.glob(pattern)):
                if path.is_file():
                    result.append((technique_id, path, name))
    return result


def run_pipeline() -> pd.DataFrame:
    """
    Discover all raw logs, load, normalize, add derived columns, concatenate.
    Saves master_events.csv and master_events.parquet to data/processed/.
    Returns the master DataFrame.
    """
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    discovered = _discover_files()
    if not discovered:
        logger.warning("No log files discovered under %s", RAW_DIR)
        return pd.DataFrame()

    normalized_dfs = []
    for technique_id, filepath, source_type in discovered:
        source_file = filepath.name
        try:
            if source_type == "sysmon":
                raw = load_sysmon(filepath, technique_id, source_file)
            elif source_type == "powershell":
                raw = load_powershell(filepath, technique_id, source_file)
            else:
                raw = load_falcon(filepath, technique_id, source_file)
            if raw.empty:
                continue
            norm = normalize_to_schema(raw, source_type)
            if not norm.empty:
                normalized_dfs.append(norm)
        except Exception as e:
            logger.warning("Pipeline failed for %s %s: %s", technique_id, filepath, e)

    if not normalized_dfs:
        master = pd.DataFrame()
    else:
        master = pd.concat(normalized_dfs, ignore_index=True)
        master = _add_derived_columns(master)

    # Save
    if not master.empty:
        master.to_csv(PROCESSED_DIR / "master_events.csv", index=False)
        try:
            master.to_parquet(PROCESSED_DIR / "master_events.parquet", index=False)
        except Exception as e:
            logger.info("Parquet save skipped (pyarrow?): %s", e)
    return master
