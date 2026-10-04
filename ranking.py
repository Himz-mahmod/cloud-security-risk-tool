"""
ranking.py

Algorithms and Data Structures enhancement for the Cloud Security Risk
Assessment Tool.

This module addresses two weaknesses identified in the Milestone One code
review of risk_calculator.py and app.py:

1. The original Priority Dashboard sorted the *entire* findings table
   with pandas' sort_values() every time it rendered, purely to display
   the top 5 "quick wins." That's an O(m log m) operation when only the
   top n items are actually needed. get_top_priority_controls() below
   replaces that with a bounded heap, giving O(m log n) instead --
   meaningfully cheaper as the number of findings (m) grows relative to
   the small number of results requested (n).

2. The original priority formula (Risk Score / Effort) treated every
   control identically regardless of category or compliance status. A
   "Non-compliant" finding and a "Compliant" finding with the same raw
   Likelihood/Impact/Effort scored identically, even though a compliant
   control's residual risk should be much lower.
   calculate_weighted_priority_score() below adds a category weight and
   a status multiplier on top of the original formula.

Both enhancements are deliberately kept separate from risk_calculator.py
so the original, simpler scoring functions remain intact, testable, and
usable on their own -- this module builds on top of them rather than
replacing them.
"""

import heapq

from risk_calculator import calculate_priority_score

# Heuristic category weights: how much a control's category tends to
# raise or lower the real-world blast radius of a compliance gap,
# relative to a neutral baseline of 1.0. These are subjective estimates
# based on common incident patterns (e.g., an identity/access gap tends
# to enable full account takeover, while a governance gap is procedural
# and slower to translate into direct compromise) -- not an empirically
# derived model. Calibrating these against real incident data is a
# documented limitation, not a finished product.
CATEGORY_WEIGHTS = {
    "Identity & Access Management": 1.3,
    "Access Control": 1.2,
    "Data Protection": 1.2,
    "Network Security": 1.1,
    "Patch Management": 1.0,
    "Vulnerability Management": 1.0,
    "System Hardening": 0.9,
    "Logging & Monitoring": 0.9,
    "Governance": 0.7,
}
DEFAULT_CATEGORY_WEIGHT = 1.0

# How much of a finding's risk is considered "resolved" by its current
# compliance status. A Non-compliant control keeps its full risk; a
# Partial control's risk is reduced but not eliminated; a Compliant
# control's residual risk is small but not assumed to be exactly zero
# (compensating controls can still fail).
STATUS_MULTIPLIERS = {
    "Non-compliant": 1.0,
    "Partial": 0.6,
    "Compliant": 0.1,
}
DEFAULT_STATUS_MULTIPLIER = 1.0


def calculate_weighted_priority_score(
    risk_score: float, effort: int, category: str, status: str
) -> float:
    """
    An enhanced Priority Score that layers a category weight and a
    compliance-status multiplier on top of the original
    Risk Score / Effort formula, so two findings with identical raw
    scores can still rank differently based on how much real-world
    blast radius their category tends to carry and how much of that
    risk their current status has already mitigated.
    """
    category_weight = CATEGORY_WEIGHTS.get(category, DEFAULT_CATEGORY_WEIGHT)
    status_multiplier = STATUS_MULTIPLIERS.get(status, DEFAULT_STATUS_MULTIPLIER)
    weighted_risk = risk_score * category_weight * status_multiplier
    base_score = calculate_priority_score(weighted_risk, effort)
    return round(base_score, 2)


def get_top_priority_controls(findings, n: int = 5, score_field: str = "Priority Score"):
    """
    Returns the top n findings ranked by score_field, using a bounded
    min-heap of size n instead of sorting the entire dataset.

    findings: any iterable of dict-like rows (a list of dicts, or the
              result of DataFrame.to_dict("records")).
    n: how many top results are needed (the "k" in O(m log k)).
    score_field: which numeric field to rank by.

    Complexity: O(m log n), where m is the number of findings and n is
    the number requested -- versus O(m log m) for a full sort, which is
    what the original Priority Dashboard did. This matters once m grows
    much larger than n, which is exactly the "small quick-wins list out
    of a large risk register" scenario this tool is built for.

    Tie-breaking is deterministic: higher Priority Score first, then
    higher Risk Score, then alphabetically by Control Name, so two runs
    over the same data always produce the same order.
    """
    findings = list(findings)
    if n <= 0 or not findings:
        return []

    heap = []  # bounded min-heap of size <= n
    for insertion_order, row in enumerate(findings):
        # Store the RAW (non-negated) sort value. A plain min-heap's
        # root (heap[0]) is always the *smallest* item -- which, for
        # un-negated (score, risk, order) tuples, is exactly the
        # *worst* of the n items we are currently keeping. That is
        # precisely what we want at the root: something cheap to
        # compare a new candidate against, and cheap to evict.
        sort_value = (row[score_field], row["Risk Score"], insertion_order)
        candidate = (sort_value, row)

        if len(heap) < n:
            heapq.heappush(heap, candidate)
        elif sort_value > heap[0][0]:
            # The new candidate beats the current worst-of-kept, so it
            # evicts it. heapreplace is a single O(log n) pop+push.
            heapq.heapreplace(heap, candidate)

    # Final, human-facing order: best score first, tie-broken by Risk
    # Score, then alphabetically by Control Name for full determinism
    # (the insertion_order used inside the heap is not a meaningful
    # business tie-break, so it is not used here).
    top_n = sorted(
        heap,
        key=lambda entry: (
            -entry[1][score_field],
            -entry[1]["Risk Score"],
            entry[1]["Control Name"],
        ),
    )
    return [entry[1] for entry in top_n]
