"""
Configuration and folder layout for MITRE ATT&CK log loading.
Add new techniques by appending to TECHNIQUE_FOLDERS and placing files in data/raw/<technique_id>/.
"""
from pathlib import Path

# Technique IDs (ground truth from folder names); do not generalize beyond these for now.
TECHNIQUE_FOLDERS = [
    "T1059.001",  # Command and Scripting Interpreter: PowerShell
    "T1003.001",  # OS Credential Dumping (LSASS)
    "T1003.003",  # OS Credential Dumping (NTDS)
    "T1547.001",  # Boot or Logon Autostart: Registry Run Keys / Startup Folder
]

# Paths relative to project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = PROJECT_ROOT / "data" / "raw"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"

# File patterns: (pattern_name, glob) for discovery. Support both .log and .txt.
FILE_PATTERNS = {
    "sysmon": "windows-sysmon.*",
    "powershell": "windows-powershell.*",
    "falcon": "crowdstrike_falcon.*",
}

# Allowed extensions for raw logs
RAW_EXTENSIONS = (".log", ".txt")
