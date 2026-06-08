"""
Generate human-readable explanation from predicted technique, confidence, and reasons.
"""


def generate_explanation(
    predicted_technique: str,
    confidence_score: float,
    reasons: list[str],
) -> str:
    """
    Build explanation string, e.g.:
    "High confidence T1059.001: Detected base64 pattern (+30), PowerShell process (+20) -> total 85%"
    """
    if not reasons:
        return f"{predicted_technique} ({confidence_score}%): No matching rules"
    confidence_label = (
        "High confidence"
        if confidence_score >= 70
        else "Medium confidence"
        if confidence_score >= 40
        else "Low confidence"
    )
    reason_str = ", ".join(reasons[:5])  # Limit to 5 reasons
    if len(reasons) > 5:
        reason_str += f" (+{len(reasons) - 5} more)"
    return f"{confidence_label} {predicted_technique}: {reason_str} -> total {confidence_score}%"
