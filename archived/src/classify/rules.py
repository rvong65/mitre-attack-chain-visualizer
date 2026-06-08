"""
Rule definitions: feature weights and conditions per MITRE technique.
Each rule: (feature_name, weight, comment for explanation).
Comments explain real-world behavior (e.g., base64 = obfuscated PowerShell).
"""
# T1059.001: Command and Scripting Interpreter - PowerShell
# Base64/encoded commands often indicate obfuscated payloads; Invoke-* common in malicious scripts
RULES_T1059_001 = [
    ("has_base64", 30, "Base64 pattern in cmdline (obfuscated PowerShell payloads)"),
    ("has_enc_flags", 25, "Encoded command flags (-enc, -EncodedCommand, -nop, -w hidden)"),
    ("has_invoke_keywords", 25, "Invoke-Expression/Invoke-WebRequest (common in scripts)"),
    ("has_powershell_process", 20, "PowerShell in process path or cmdline"),
    ("is_office_to_powershell", 15, "Office app spawning cmd/PowerShell (macro evasion chain)"),
    ("is_office_spawn", 10, "Parent is Office app (winword, excel, powerpnt)"),
    ("cmdline_has_url", 5, "URL in cmdline (download cradle)"),
]
# Numeric bonus: cmdline_entropy > 4.0 -> +10 (high randomness suggests obfuscation)
T1059_ENTROPY_THRESHOLD = 4.0
T1059_ENTROPY_BONUS = 10

# T1003.001 / T1003.003: OS Credential Dumping (LSASS / NTDS)
# procdump/minidump/comsvcs.dll are common LSASS dump methods
RULES_T1003 = [
    ("has_lsass_mention", 30, "LSASS mentioned (credential dumping target)"),
    ("has_procdump_minidump", 25, "procdump/minidump/.dmp (dump file indicators)"),
    ("has_comsvcs_rundll32", 25, "comsvcs.dll or rundll32 MiniDump (LSASS dump)"),
    ("has_handle_taskmgr_parent", 15, "handle.exe or taskmgr.exe parent"),
]
# file_path contains .dmp -> +10 (checked in scorer)

# T1547.001: Boot or Logon Autostart - Registry Run Keys
RULES_T1547_001 = [
    ("has_run_registry", 35, "Registry Run/RunOnce key (persistence)"),
    ("has_set_itemproperty", 25, "Set-ItemProperty with Run/Startup (PowerShell persistence)"),
    ("has_reg_exe", 20, "reg.exe process (registry modification)"),
    ("is_persistence_attempt", 15, "Persistence pattern in registry/cmdline"),
    ("is_elevated", 5, "SYSTEM or NT AUTHORITY user"),
]

# Fallback: max score below this -> Unknown
UNKNOWN_THRESHOLD = 25

# Cap per technique
SCORE_CAP = 95

# Tie-break order (most specific first)
TECHNIQUE_ORDER = ["T1003.001", "T1003.003", "T1547.001", "T1059.001"]
