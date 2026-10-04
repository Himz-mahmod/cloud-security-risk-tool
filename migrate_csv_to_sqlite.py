"""
migrate_csv_to_sqlite.py

One-time migration of the data the CSV-based versions of this tool
created (findings.csv, and users.json from the Milestone Two version)
into the SQLite database.

Usage:
    python migrate_csv_to_sqlite.py
    python migrate_csv_to_sqlite.py --findings findings.csv --users users.json --db risk_tool.db

Design notes:
- Everything runs in one transaction. If anything unexpected fails, the
  database is rolled back and left exactly as it was.
- Scores are recomputed from Likelihood, Impact, Effort, Category, and
  Status instead of trusting the CSV. Version 1 files have no weighted
  score at all, and recomputing keeps old and new rows consistent.
- Rows that fail validation or duplicate an existing assessment are
  skipped and counted, not allowed to stop the run. A file with the wrong
  columns is different: it stops the run with a clear message.
- CSV files saved by Excel (BOM, Windows line endings, semicolon
  delimiters) are read correctly.
- Running it twice is safe: the second run finds every row already
  present and imports nothing.
"""

import argparse
import json
import os
import sqlite3

from auth import ensure_default_admin
from database import (
    DuplicateAssessmentError,
    add_assessment,
    create_user,
    ensure_disabled_user,
    get_connection,
    read_csv_rows,
)
from validators import ValidationError


def migrate_users_json(conn: sqlite3.Connection, path: str) -> int:
    """
    Copies accounts from the old users.json ({username: "salt$hash"}).
    The hashes use the same format as the new table, so they move over
    unchanged and existing passwords keep working. Returns users imported.
    """
    if not os.path.exists(path):
        return 0
    with open(path, "r", encoding="utf-8") as f:
        users = json.load(f)
    imported = 0
    for username, password_hash in users.items():
        if create_user(conn, username, password_hash, commit=False):
            imported += 1
    return imported


def migrate_findings_csv(conn: sqlite3.Connection, path: str,
                         default_username: str = "admin") -> dict:
    """
    Imports legacy findings. Returns counts of imported, duplicate, and
    invalid rows. The caller is responsible for committing.

    Rows from the Version 1 file have no "Assessed By" column and are
    attributed to default_username. Rows that name a user with no account
    get a login-disabled placeholder account so the foreign key holds.
    """
    summary = {"imported": 0, "duplicates": 0, "invalid": 0}
    if not os.path.exists(path):
        return summary

    rows = read_csv_rows(path, required_columns=("Control Name", "Category"))
    ensure_default_admin(conn, commit=False)

    for row in rows:
        username = (row.get("Assessed By") or "").strip() or default_username
        try:
            ensure_disabled_user(conn, username)
            add_assessment(
                conn,
                control_name=row.get("Control Name"),
                category=row.get("Category"),
                likelihood=row.get("Likelihood"),
                impact=row.get("Impact"),
                effort=row.get("Effort"),
                status=row.get("Status"),
                username=username,
                commit=False,
            )
            summary["imported"] += 1
        except DuplicateAssessmentError:
            summary["duplicates"] += 1
        except (ValidationError, AttributeError):
            summary["invalid"] += 1
    return summary


def run_migration(db_path: str, findings_path: str, users_path: str) -> dict:
    """Runs the whole migration in a single transaction."""
    conn = get_connection(db_path)
    try:
        users_imported = migrate_users_json(conn, users_path)
        summary = migrate_findings_csv(conn, findings_path)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    summary["users_imported"] = users_imported
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[1])
    parser.add_argument("--findings", default="findings.csv")
    parser.add_argument("--users", default="users.json")
    parser.add_argument("--db", default=None, help="SQLite file (default: risk_tool.db)")
    args = parser.parse_args()

    try:
        result = run_migration(args.db, args.findings, args.users)
    except ValueError as exc:
        raise SystemExit(f"Migration stopped, nothing was changed: {exc}")
    print(f"Users imported:        {result['users_imported']}")
    print(f"Assessments imported:  {result['imported']}")
    print(f"Skipped (duplicates):  {result['duplicates']}")
    print(f"Skipped (invalid):     {result['invalid']}")


if __name__ == "__main__":
    main()
