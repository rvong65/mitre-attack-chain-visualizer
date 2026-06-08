"""
Score each row against technique rules; return predicted technique, confidence, reasons.
"""
from .rules import (
    RULES_T1003,
    RULES_T1059_001,
    RULES_T1547_001,
    SCORE_CAP,
    T1059_ENTROPY_BONUS,
    T1059_ENTROPY_THRESHOLD,
    TECHNIQUE_ORDER,
    UNKNOWN_THRESHOLD,
)


def _get_bool(row, key: str, default: bool = False) -> bool:
    """Safely get boolean from row (handles CSV bool-as-string)."""
    v = row.get(key, default)
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.lower() in ("true", "1", "yes")
    return bool(v)


def _get_float(row, key: str, default: float = 0.0) -> float:
    """Safely get float from row."""
    v = row.get(key, default)
    if v is None or (isinstance(v, float) and (v != v)):  # NaN
        return default
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _score_t1059(row) -> tuple[float, list[str]]:
    """Score for T1059.001 (PowerShell)."""
    score = 0.0
    reasons = []
    for feat, weight, comment in RULES_T1059_001:
        if _get_bool(row, feat):
            score += weight
            reasons.append(f"{comment} (+{weight})")
    # High entropy bonus
    ent = _get_float(row, "cmdline_entropy")
    if ent >= T1059_ENTROPY_THRESHOLD:
        score += T1059_ENTROPY_BONUS
        reasons.append(f"High cmdline entropy {ent:.1f} (+{T1059_ENTROPY_BONUS})")
    return min(score, SCORE_CAP), reasons


def _score_t1003(row) -> tuple[float, list[str]]:
    """Score for T1003.001 / T1003.003 (Credential Dumping). Same rules for both."""
    score = 0.0
    reasons = []
    for feat, weight, comment in RULES_T1003:
        if _get_bool(row, feat):
            score += weight
            reasons.append(f"{comment} (+{weight})")
    # file_path contains .dmp
    fp = str(row.get("file_path", "") or "")
    if ".dmp" in fp.lower():
        score += 10
        reasons.append("file_path contains .dmp (+10)")
    return min(score, SCORE_CAP), reasons


def _score_t1547(row) -> tuple[float, list[str]]:
    """Score for T1547.001 (Registry Run Keys)."""
    score = 0.0
    reasons = []
    for feat, weight, comment in RULES_T1547_001:
        if _get_bool(row, feat):
            score += weight
            reasons.append(f"{comment} (+{weight})")
    return min(score, SCORE_CAP), reasons


def score_technique(row: dict) -> tuple[str, float, list[str]]:
    """
    Score row against all techniques. Return (predicted_technique, confidence_score, reasons).
    Uses TECHNIQUE_ORDER for tie-break.
    """
    scores = {}
    # T1003.001 and T1003.003 share rules; score once, assign to both for tie-break
    s1003, r1003 = _score_t1003(row)
    scores["T1003.001"] = (s1003, r1003)
    scores["T1003.003"] = (s1003, r1003)
    scores["T1547.001"] = _score_t1547(row)
    scores["T1059.001"] = _score_t1059(row)

    best_tech = None
    best_score = 0.0
    best_reasons = []

    for tech in TECHNIQUE_ORDER:
        sc, reas = scores[tech]
        if sc > best_score:
            best_score = sc
            best_tech = tech
            best_reasons = reas

    if best_score < UNKNOWN_THRESHOLD:
        best_tech = "Unknown"
        best_reasons = ["No strong rule matches"]
    elif best_tech is None:
        best_tech = "Unknown"
        best_reasons = ["No rules fired"]

    return best_tech, round(min(best_score, 100), 1), best_reasons
