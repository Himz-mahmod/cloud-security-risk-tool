"""
risk_calculator.py

Core scoring logic for the Cloud Security Risk Assessment Tool.

Kept intentionally simple for Version 1 (CS 3XX capstone baseline).
Reserved for CS 499 enhancement: weighted scoring models, CIS/NIST
control mapping, and a more sophisticated priority algorithm
(e.g. factoring in asset criticality or exposure).
"""


def calculate_risk_score(likelihood: int, impact: int) -> int:
    """
    Risk Score = Likelihood x Impact

    likelihood: 1-5 (how likely the control gap is to be exploited)
    impact:     1-5 (how damaging exploitation would be)

    Returns an integer between 1 and 25.
    """
    return likelihood * impact


def calculate_priority_score(risk_score: float, effort: int) -> float:
    """
    Priority Score = Risk Score / Implementation Effort

    This is the key idea behind the tool: a control isn't just ranked by
    how risky it is, but by how much risk reduction you get per unit of
    effort. A small org with limited staff/budget should fix the
    highest risk score using the least effort first.

    effort: 1-3 (1 = low effort/quick win, 3 = high effort/major project)
    """
    if effort <= 0:
        effort = 1  # guard against divide-by-zero from bad input
    return risk_score / effort


def get_priority_level(risk_score: int) -> str:
    """
    Maps a raw risk score (1-25) to a qualitative priority level.

    20-25 -> Critical
    12-19 -> High
    6-11  -> Medium
    1-5   -> Low
    """
    if risk_score >= 20:
        return "Critical"
    elif risk_score >= 12:
        return "High"
    elif risk_score >= 6:
        return "Medium"
    else:
        return "Low"
