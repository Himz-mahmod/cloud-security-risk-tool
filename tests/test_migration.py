import csv
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from auth import authenticate, register_user, _hash_password
from database import get_connection, list_assessments
from migrate_csv_to_sqlite import (
    migrate_findings_csv,
    migrate_users_json,
    run_migration,
)

V1_HEADER = [
    "Control Name", "Category", "Likelihood", "Impact", "Effort", "Status",
    "Risk Score", "Priority Score", "Priority Level",
]


def write_csv(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)


def test_version1_csv_imports_and_scores_are_recomputed(tmp_path, conn):
    path = tmp_path / "findings.csv"
    # The Priority Score in the file (999) is wrong on purpose.
    write_csv(path, V1_HEADER, [
        ["Enable MFA", "Identity & Access Management", 5, 5, 1, "Non-compliant", 25, 999, "Critical"],
    ])
    summary = migrate_findings_csv(conn, str(path))
    assert summary == {"imported": 1, "duplicates": 0, "invalid": 0}

    row = list_assessments(conn)[0]
    assert row["Priority Score"] == 25.0
    assert row["Weighted Priority Score"] == 32.5
    assert row["Assessed By"] == "admin"


def test_duplicates_and_invalid_rows_are_skipped_not_fatal(tmp_path, conn):
    path = tmp_path / "findings.csv"
    write_csv(path, V1_HEADER, [
        ["Enable MFA", "Access Control", 4, 4, 1, "Partial", 16, 16, "High"],
        ["enable mfa", "access control", 4, 4, 1, "Partial", 16, 16, "High"],   # duplicate
        ["Bad score", "Access Control", 9, 4, 1, "Partial", 36, 36, "High"],     # out of range
        ["Bad status", "Access Control", 3, 3, 1, "Unknown", 9, 9, "Medium"],    # bad status
        ["", "Access Control", 3, 3, 1, "Partial", 9, 9, "Medium"],              # empty name
        ["No numbers", "Access Control", "", "", "", "Partial", 0, 0, "Low"],    # blank numbers
    ])
    summary = migrate_findings_csv(conn, str(path))
    assert summary == {"imported": 1, "duplicates": 1, "invalid": 4}


def test_milestone_two_csv_keeps_assessed_by_and_creates_disabled_user(tmp_path, conn):
    path = tmp_path / "findings.csv"
    write_csv(path, V1_HEADER + ["Assessed By"], [
        ["Enable MFA", "Access Control", 4, 4, 1, "Partial", 16, 16, "High", "tanvir"],
    ])
    migrate_findings_csv(conn, str(path))
    assert list_assessments(conn)[0]["Assessed By"] == "tanvir"
    # The placeholder account exists but cannot be used to log in.
    assert authenticate("tanvir", "!", conn) is False


def test_missing_files_import_nothing(tmp_path, conn):
    assert migrate_findings_csv(conn, str(tmp_path / "nope.csv")) == {
        "imported": 0, "duplicates": 0, "invalid": 0,
    }
    assert migrate_users_json(conn, str(tmp_path / "nope.json")) == 0


def test_users_json_hashes_move_over_and_passwords_still_work(tmp_path, conn):
    path = tmp_path / "users.json"
    path.write_text(json.dumps({"admin": _hash_password("MyRealPassword1")}))
    assert migrate_users_json(conn, str(path)) == 1
    assert authenticate("admin", "MyRealPassword1", conn) is True
    assert authenticate("admin", "changeme123", conn) is False


def test_migration_is_repeatable(tmp_path):
    db = str(tmp_path / "m.db")
    findings = tmp_path / "findings.csv"
    users = tmp_path / "users.json"
    write_csv(findings, V1_HEADER, [
        ["Enable MFA", "Access Control", 4, 4, 1, "Partial", 16, 16, "High"],
    ])
    users.write_text(json.dumps({"admin": _hash_password("MyRealPassword1")}))

    first = run_migration(db, str(findings), str(users))
    second = run_migration(db, str(findings), str(users))
    assert first["imported"] == 1 and first["users_imported"] == 1
    assert second["imported"] == 0 and second["duplicates"] == 1 and second["users_imported"] == 0


def test_failure_rolls_back_everything(tmp_path, monkeypatch):
    db = str(tmp_path / "r.db")
    findings = tmp_path / "findings.csv"
    write_csv(findings, V1_HEADER, [
        ["Enable MFA", "Access Control", 4, 4, 1, "Partial", 16, 16, "High"],
    ])

    import migrate_csv_to_sqlite as mod

    def boom(*args, **kwargs):
        raise RuntimeError("simulated crash")

    original = mod.migrate_findings_csv

    def crash_after_import(conn, path, default_username="admin"):
        original(conn, path, default_username)  # rows inserted, not yet committed
        boom()

    monkeypatch.setattr(mod, "migrate_findings_csv", crash_after_import)
    with pytest.raises(RuntimeError):
        mod.run_migration(db, str(findings), str(tmp_path / "none.json"))

    conn = get_connection(db)
    assert list_assessments(conn) == []
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
    conn.close()


# ---------------------------------------------------------------------------
# Files saved by Excel
# ---------------------------------------------------------------------------

EXCEL_ROW = ["Enable MFA", "Identity & Access Management", 5, 5, 1, "Non-compliant", 25, 25.0, "Critical"]


def test_excel_csv_with_bom_and_windows_line_endings_imports(tmp_path, conn):
    path = tmp_path / "findings.csv"
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f, lineterminator="\r\n")
        writer.writerow(V1_HEADER)
        writer.writerow(EXCEL_ROW)
    assert path.read_bytes()[:3] == b"\xef\xbb\xbf"
    assert migrate_findings_csv(conn, str(path))["imported"] == 1


def test_semicolon_delimited_csv_imports(tmp_path, conn):
    # Excel on a Danish-locale computer saves CSV files with semicolons.
    path = tmp_path / "findings.csv"
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f, delimiter=";", lineterminator="\r\n")
        writer.writerow(V1_HEADER)
        writer.writerow(EXCEL_ROW)
    assert migrate_findings_csv(conn, str(path))["imported"] == 1


def test_file_with_wrong_columns_fails_loudly_and_changes_nothing(tmp_path):
    db = str(tmp_path / "w.db")
    path = tmp_path / "findings.csv"
    write_csv(path, ["Name", "Score"], [["Enable MFA", 5]])
    with pytest.raises(ValueError, match="missing required column"):
        run_migration(db, str(path), str(tmp_path / "none.json"))
    conn = get_connection(db)
    assert list_assessments(conn) == []
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
    conn.close()


def test_empty_file_fails_loudly(tmp_path, conn):
    path = tmp_path / "findings.csv"
    path.write_text("")
    with pytest.raises(ValueError, match="empty"):
        migrate_findings_csv(conn, str(path))
