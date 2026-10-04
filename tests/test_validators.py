import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pandas as pd
import pytest
from validators import (
    ValidationError,
    validate_score,
    validate_control_name,
    validate_status,
    validate_category,
    is_duplicate,
)


def test_validate_score_in_range():
    assert validate_score(3, 1, 5, "Likelihood") == 3


def test_validate_score_out_of_range():
    with pytest.raises(ValidationError):
        validate_score(6, 1, 5, "Likelihood")


def test_validate_score_non_numeric():
    with pytest.raises(ValidationError):
        validate_score("abc", 1, 5, "Likelihood")


def test_validate_control_name_valid():
    assert validate_control_name("  Enable MFA  ") == "Enable MFA"


def test_validate_control_name_empty():
    with pytest.raises(ValidationError):
        validate_control_name("   ")


def test_validate_control_name_too_long():
    with pytest.raises(ValidationError):
        validate_control_name("x" * 200)


def test_validate_status_valid():
    assert validate_status("Partial") == "Partial"


def test_validate_status_invalid():
    with pytest.raises(ValidationError):
        validate_status("Unknown")


def test_is_duplicate_detects_case_insensitive_match():
    df = pd.DataFrame(
        [{"Control Name": "Enable MFA", "Category": "Identity & Access Management"}]
    )
    assert is_duplicate(df, "enable mfa", "identity & access management") is True


def test_is_duplicate_returns_false_for_new_entry():
    df = pd.DataFrame(
        [{"Control Name": "Enable MFA", "Category": "Identity & Access Management"}]
    )
    assert is_duplicate(df, "Enable disk encryption", "Data Protection") is False


def test_is_duplicate_empty_dataframe():
    assert is_duplicate(pd.DataFrame(), "Enable MFA", "Access Control") is False


def test_validate_category_valid():
    assert validate_category("  Access Control ") == "Access Control"


def test_validate_category_empty_or_none():
    with pytest.raises(ValidationError):
        validate_category("   ")
    with pytest.raises(ValidationError):
        validate_category(None)


def test_validate_category_too_long():
    with pytest.raises(ValidationError):
        validate_category("x" * 101)
