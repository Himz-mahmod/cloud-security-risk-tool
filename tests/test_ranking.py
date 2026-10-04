import sys
import os
import random

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ranking import (
    calculate_weighted_priority_score,
    get_top_priority_controls,
    CATEGORY_WEIGHTS,
    STATUS_MULTIPLIERS,
)


def make_row(name, priority_score, risk_score, category="Access Control"):
    return {
        "Control Name": name,
        "Category": category,
        "Priority Score": priority_score,
        "Risk Score": risk_score,
    }


# ---------------------------------------------------------------------------
# calculate_weighted_priority_score
# ---------------------------------------------------------------------------

def test_weighted_score_non_compliant_full_weight():
    # Non-compliant keeps the full multiplier (1.0), so with a neutral
    # category weight the result should equal the unweighted formula.
    score = calculate_weighted_priority_score(
        risk_score=12, effort=2, category="Patch Management", status="Non-compliant"
    )
    assert score == 6.0  # (12 * 1.0 * 1.0) / 2


def test_weighted_score_compliant_much_lower_than_non_compliant():
    non_compliant = calculate_weighted_priority_score(12, 2, "Patch Management", "Non-compliant")
    compliant = calculate_weighted_priority_score(12, 2, "Patch Management", "Compliant")
    assert compliant < non_compliant
    assert compliant == round((12 * 1.0 * 0.1) / 2, 2)


def test_weighted_score_higher_weight_category_scores_higher():
    iam_score = calculate_weighted_priority_score(10, 1, "Identity & Access Management", "Non-compliant")
    governance_score = calculate_weighted_priority_score(10, 1, "Governance", "Non-compliant")
    assert iam_score > governance_score


def test_weighted_score_unknown_category_uses_default_weight():
    score = calculate_weighted_priority_score(10, 1, "Some New Category", "Non-compliant")
    assert score == 10.0  # default weight 1.0, default status multiplier n/a here


def test_all_declared_category_weights_are_positive():
    assert all(w > 0 for w in CATEGORY_WEIGHTS.values())


def test_all_status_multipliers_between_zero_and_one():
    assert all(0 <= m <= 1 for m in STATUS_MULTIPLIERS.values())


# ---------------------------------------------------------------------------
# get_top_priority_controls
# ---------------------------------------------------------------------------

def test_get_top_priority_controls_basic_ordering():
    rows = [
        make_row("A", priority_score=5, risk_score=10),
        make_row("B", priority_score=9, risk_score=18),
        make_row("C", priority_score=7, risk_score=14),
    ]
    top = get_top_priority_controls(rows, n=2)
    assert [r["Control Name"] for r in top] == ["B", "C"]


def test_get_top_priority_controls_respects_n():
    rows = [make_row(f"Control{i}", priority_score=i, risk_score=i * 2) for i in range(20)]
    top = get_top_priority_controls(rows, n=5)
    assert len(top) == 5
    assert [r["Control Name"] for r in top] == [
        "Control19", "Control18", "Control17", "Control16", "Control15"
    ]


def test_get_top_priority_controls_deterministic_tie_break_by_risk_then_name():
    rows = [
        make_row("Zebra", priority_score=10, risk_score=10),
        make_row("Alpha", priority_score=10, risk_score=10),
        make_row("Mango", priority_score=10, risk_score=20),  # higher risk should win tie
    ]
    top = get_top_priority_controls(rows, n=3)
    # Mango has higher Risk Score, so it wins the Priority Score tie.
    # Alpha and Zebra are equal on both, so alphabetical breaks the tie.
    assert [r["Control Name"] for r in top] == ["Mango", "Alpha", "Zebra"]


def test_get_top_priority_controls_empty_input():
    assert get_top_priority_controls([], n=5) == []


def test_get_top_priority_controls_n_zero():
    rows = [make_row("A", 5, 10)]
    assert get_top_priority_controls(rows, n=0) == []


def test_get_top_priority_controls_n_larger_than_dataset():
    rows = [make_row("A", 5, 10), make_row("B", 9, 18)]
    top = get_top_priority_controls(rows, n=100)
    assert len(top) == 2


def test_get_top_priority_controls_matches_full_sort_on_random_data():
    """
    Cross-check: the heap-based top-n must match what a naive full sort
    would produce, for many random datasets. This is the correctness
    guarantee that justifies replacing the full sort in app.py.
    """
    random.seed(42)
    for _ in range(25):
        rows = [
            make_row(f"C{i}", priority_score=round(random.uniform(0, 25), 2),
                      risk_score=random.randint(1, 25))
            for i in range(random.randint(1, 30))
        ]
        n = random.randint(1, 10)

        heap_result = get_top_priority_controls(rows, n=n)
        full_sort_result = sorted(
            rows,
            key=lambda r: (-r["Priority Score"], -r["Risk Score"], r["Control Name"]),
        )[:n]

        assert [r["Control Name"] for r in heap_result] == [
            r["Control Name"] for r in full_sort_result
        ]
