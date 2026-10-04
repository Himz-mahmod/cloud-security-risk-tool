"""
validators.py

Defensive input validation for the Cloud Security Risk Assessment Tool.

These checks are intentionally independent of the Streamlit UI widgets
(sliders/selectboxes). The UI already constrains values in Version 1, but
that is not real protection: any future entry point that bypasses the UI
(a CSV import, an API, a database migration) would have no safety net at
all. Enforcing the same rules here means the rules travel with the data,
not with a particular form.
"""

import re

VALID_STATUSES = {"Non-compliant", "Partial", "Compliant"}
MAX_NAME_LENGTH = 150
MAX_CATEGORY_LENGTH = 100


class ValidationError(Exception):
    """Raised when submitted assessment data fails validation."""


def validate_score(value, min_value: int, max_value: int, field_name: str) -> int:
    """Ensures a score is an integer within an inclusive range."""
    try:
        value = int(value)
    except (TypeError, ValueError):
        raise ValidationError(f"{field_name} must be a whole number.")
    if not (min_value <= value <= max_value):
        raise ValidationError(
            f"{field_name} must be between {min_value} and {max_value}, got {value}."
        )
    return value


def validate_control_name(name: str) -> str:
    """Ensures a control name is present, a sane length, and printable."""
    if name is None:
        raise ValidationError("Control name is required.")
    name = name.strip()
    if not name:
        raise ValidationError("Control name cannot be empty.")
    if len(name) > MAX_NAME_LENGTH:
        raise ValidationError(f"Control name must be under {MAX_NAME_LENGTH} characters.")
    # Reject stray control characters (e.g., an accidental paste of binary
    # data) while still allowing normal punctuation like "/", "(", ")".
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", name):
        raise ValidationError("Control name contains invalid characters.")
    return name


def validate_category(category: str) -> str:
    """Ensures a category is present and a sane length before it reaches storage."""
    if category is None or not str(category).strip():
        raise ValidationError("Category is required.")
    category = str(category).strip()
    if len(category) > MAX_CATEGORY_LENGTH:
        raise ValidationError(f"Category must be under {MAX_CATEGORY_LENGTH} characters.")
    return category


def validate_status(status: str) -> str:
    """Ensures status is one of the accepted values, not a free-text string."""
    if status not in VALID_STATUSES:
        raise ValidationError(f"Status must be one of {sorted(VALID_STATUSES)}.")
    return status


def is_duplicate(findings_df, control_name: str, category: str) -> bool:
    """
    Returns True if this control name + category has already been
    assessed (case-insensitive), to catch accidental double entry before
    it pollutes the risk register.
    """
    if findings_df is None or len(findings_df) == 0:
        return False
    match = findings_df[
        (findings_df["Control Name"].str.strip().str.lower() == control_name.strip().lower())
        & (findings_df["Category"].str.strip().str.lower() == category.strip().lower())
    ]
    return len(match) > 0
