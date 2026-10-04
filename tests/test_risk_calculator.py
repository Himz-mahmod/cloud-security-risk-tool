import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from risk_calculator import calculate_risk_score, calculate_priority_score, get_priority_level


def test_calculate_risk_score_basic():
    assert calculate_risk_score(3, 4) == 12


def test_calculate_risk_score_bounds():
    assert calculate_risk_score(1, 1) == 1
    assert calculate_risk_score(5, 5) == 25


def test_calculate_priority_score():
    assert calculate_priority_score(20, 2) == 10.0
    assert calculate_priority_score(9, 3) == 3.0


def test_calculate_priority_score_zero_effort_guard():
    # An effort of 0 should never raise ZeroDivisionError; it should
    # fall back to treating effort as 1.
    result = calculate_priority_score(10, 0)
    assert result == 10.0


@pytest.mark.parametrize(
    "score,expected",
    [
        (25, "Critical"),
        (20, "Critical"),
        (19, "High"),
        (12, "High"),
        (11, "Medium"),
        (6, "Medium"),
        (5, "Low"),
        (1, "Low"),
    ],
)
def test_get_priority_level_thresholds(score, expected):
    assert get_priority_level(score) == expected
