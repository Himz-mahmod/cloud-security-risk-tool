import os
import sqlite3
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from database import (
    DuplicateAssessmentError,
    add_assessment,
    assessment_exists,
    clear_assessments,
    get_connection,
    list_assessments,
    list_library_controls,
    seed_controls_from_csv,
)
from validators import ValidationError

CONTROLS_CSV = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "controls.csv")
)


def add(conn, name="Enable MFA", category="Identity & Access Management",
        likelihood=5, impact=5, effort=1, status="Non-compliant", username="admin"):
    # "admin" exists only after first authentication, so create it directly.
    if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone() is None:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, 'x')", (username,)
        )
        conn.commit()
    return add_assessment(conn, name, category, likelihood, impact, effort, status, username)


# ---------------------------------------------------------------------------
# Schema, foreign keys, constraints
# ---------------------------------------------------------------------------

def test_expected_tables_exist(conn):
    tables = {
        r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    assert {"users", "controls", "assessments"} <= tables


def test_foreign_keys_are_enabled(conn):
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_init_is_idempotent(tmp_path):
    path = str(tmp_path / "again.db")
    get_connection(path).close()
    get_connection(path).close()  # second call must not fail or duplicate anything


def test_foreign_key_rejects_assessment_for_missing_control(conn):
    conn.execute("INSERT INTO users (username, password_hash) VALUES ('u', 'x')")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """INSERT INTO assessments
               (control_id, assessed_by, likelihood, impact, effort, status,
                risk_score, priority_score, weighted_priority_score, priority_level)
               VALUES (999, 1, 3, 3, 2, 'Partial', 9, 4.5, 4.5, 'Medium')"""
        )


def test_cannot_delete_control_that_has_an_assessment(conn):
    add(conn)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM controls")


@pytest.mark.parametrize(
    "column,value",
    [("likelihood", 6), ("likelihood", 0), ("impact", 9), ("effort", 4), ("status", "Maybe")],
)
def test_check_constraints_reject_bad_values_even_if_app_is_bypassed(conn, column, value):
    add(conn)
    values = {
        "likelihood": 3, "impact": 3, "effort": 2, "status": "Partial",
        "risk_score": 9, "priority_score": 4.5, "weighted_priority_score": 4.5,
        "priority_level": "Medium",
    }
    values[column] = value
    conn.execute("INSERT INTO controls (name, category) VALUES ('Other control', 'Governance')")
    control_id = conn.execute("SELECT id FROM controls WHERE name = 'Other control'").fetchone()[0]
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """INSERT INTO assessments
               (control_id, assessed_by, likelihood, impact, effort, status,
                risk_score, priority_score, weighted_priority_score, priority_level)
               VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (control_id, values["likelihood"], values["impact"], values["effort"],
             values["status"], values["risk_score"], values["priority_score"],
             values["weighted_priority_score"], values["priority_level"]),
        )


# ---------------------------------------------------------------------------
# add_assessment
# ---------------------------------------------------------------------------

def test_add_assessment_computes_scores_with_existing_logic(conn):
    result = add(conn, likelihood=5, impact=5, effort=1, status="Non-compliant")
    assert result["risk_score"] == 25
    assert result["priority_level"] == "Critical"
    assert result["priority_score"] == 25.0
    # Identity & Access Management weight is 1.3, Non-compliant multiplier is 1.0.
    assert result["weighted_priority_score"] == 32.5


def test_add_assessment_rejects_invalid_input_and_writes_nothing(conn):
    with pytest.raises(ValidationError):
        add(conn, likelihood=9)
    assert list_assessments(conn) == []
    assert conn.execute("SELECT COUNT(*) FROM controls").fetchone()[0] == 0


def test_add_assessment_rejects_duplicates_case_insensitively(conn):
    add(conn, name="Enable MFA", category="Access Control")
    with pytest.raises(DuplicateAssessmentError):
        add(conn, name="enable mfa", category="ACCESS CONTROL")
    assert len(list_assessments(conn)) == 1


def test_same_control_name_in_different_category_is_allowed(conn):
    add(conn, name="Enable MFA", category="Access Control")
    add(conn, name="Enable MFA", category="Governance")
    assert len(list_assessments(conn)) == 2


def test_add_assessment_unknown_user_raises(conn):
    with pytest.raises(ValueError):
        add_assessment(conn, "Enable MFA", "Access Control", 3, 3, 2, "Partial", "nobody")


def test_assessment_exists(conn):
    add(conn, name="Enable MFA", category="Access Control")
    assert assessment_exists(conn, "ENABLE mfa", "access control") is True
    assert assessment_exists(conn, "Something else", "Access Control") is False


def test_unique_constraint_is_the_backstop_for_duplicates(conn):
    add(conn, name="Enable MFA", category="Access Control")
    control_id = conn.execute("SELECT id FROM controls").fetchone()[0]
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """INSERT INTO assessments
               (control_id, assessed_by, likelihood, impact, effort, status,
                risk_score, priority_score, weighted_priority_score, priority_level)
               VALUES (?, 1, 3, 3, 2, 'Partial', 9, 4.5, 4.5, 'Medium')""",
            (control_id,),
        )


# ---------------------------------------------------------------------------
# SQL injection
# ---------------------------------------------------------------------------

INJECTION_NAME = "x'); DROP TABLE users; --"


def test_injection_attempt_in_control_name_is_stored_as_plain_text(conn):
    add(conn, name=INJECTION_NAME, category="Access Control")
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert "users" in tables
    assert list_assessments(conn)[0]["Control Name"] == INJECTION_NAME


def test_injection_attempt_in_filter_values_is_harmless(conn):
    add(conn)
    result = list_assessments(conn, levels=["Critical' OR '1'='1"])
    assert result == []
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert "assessments" in tables


def test_order_by_only_accepts_whitelisted_keys(conn):
    with pytest.raises(ValueError):
        list_assessments(conn, order_by="id; DROP TABLE users")


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------

def test_list_assessments_uses_ui_column_names(conn):
    add(conn)
    row = list_assessments(conn)[0]
    assert set(row) == {
        "Control Name", "Category", "Likelihood", "Impact", "Effort", "Status",
        "Risk Score", "Priority Score", "Weighted Priority Score",
        "Priority Level", "Assessed By",
    }
    assert row["Assessed By"] == "admin"


def test_list_assessments_filters_and_orders(conn):
    add(conn, name="A", category="Access Control", likelihood=5, impact=5)
    add(conn, name="B", category="Governance", likelihood=1, impact=1)
    add(conn, name="C", category="Access Control", likelihood=3, impact=3)

    by_risk = list_assessments(conn, order_by="risk_desc")
    assert [r["Control Name"] for r in by_risk] == ["A", "C", "B"]

    critical = list_assessments(conn, levels=["Critical"])
    assert [r["Control Name"] for r in critical] == ["A"]

    access = list_assessments(conn, categories=["access control"])
    assert {r["Control Name"] for r in access} == {"A", "C"}

    assert list_assessments(conn, levels=[]) == []


def test_clear_assessments_keeps_controls_and_users(conn):
    add(conn)
    clear_assessments(conn)
    assert list_assessments(conn) == []
    assert conn.execute("SELECT COUNT(*) FROM controls").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1


def test_seed_controls_loads_library_and_is_repeatable(conn):
    first = seed_controls_from_csv(conn, CONTROLS_CSV)
    seed_controls_from_csv(conn, CONTROLS_CSV)
    library = list_library_controls(conn)
    assert first == len(library) == 20
    assert set(library[0]) == {"Control Name", "Category", "Typical Benefit for Small Orgs"}


def test_custom_controls_do_not_appear_in_library(conn):
    seed_controls_from_csv(conn, CONTROLS_CSV)
    add(conn, name="My custom control", category="Other")
    names = [c["Control Name"] for c in list_library_controls(conn)]
    assert "My custom control" not in names


# ---------------------------------------------------------------------------
# Indexes
# ---------------------------------------------------------------------------

def test_expected_indexes_exist(conn):
    indexes = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
    assert {
        "idx_assessments_priority_level",
        "idx_assessments_weighted_score",
        "idx_assessments_assessed_by",
        "idx_controls_category",
    } <= indexes


def _plan(conn, sql, params=()):
    return " ".join(r[3] for r in conn.execute("EXPLAIN QUERY PLAN " + sql, params))


def test_priority_level_filter_uses_its_index(conn):
    add(conn)
    plan = _plan(conn, "SELECT id FROM assessments WHERE priority_level = ?", ("Critical",))
    assert "idx_assessments_priority_level" in plan


def test_top_n_by_weighted_score_uses_its_index(conn):
    add(conn)
    plan = _plan(
        conn, "SELECT id FROM assessments ORDER BY weighted_priority_score DESC LIMIT 5"
    )
    assert "idx_assessments_weighted_score" in plan


def test_seed_controls_reads_an_excel_saved_library(tmp_path, conn):
    path = tmp_path / "controls.csv"
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        f.write("Control Name;Category;Typical Benefit for Small Orgs\r\n")
        f.write("Enable MFA;Access Control;Stops most account takeovers.\r\n")
    assert seed_controls_from_csv(conn, str(path)) == 1
    assert list_library_controls(conn)[0]["Control Name"] == "Enable MFA"


def test_seed_controls_rejects_a_file_without_the_expected_columns(tmp_path, conn):
    path = tmp_path / "controls.csv"
    path.write_text("Name,Type\nEnable MFA,Access\n")
    with pytest.raises(ValueError):
        seed_controls_from_csv(conn, str(path))
