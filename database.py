"""
database.py

Databases enhancement for the Cloud Security Risk Assessment Tool.

Version 1 stored everything in flat CSV files. The Milestone One code
review found four problems with that design:

1. No relationships. Nothing tied a finding to the control it described
   or to the user who entered it, so a typo in a control name went
   unnoticed.
2. No concurrency safety. Every save rewrote the whole file, so two
   simultaneous saves could silently lose one of the writes.
3. No indexes. Every filter scanned the whole table.
4. No schema. The storage layer accepted any string in any column.

This module replaces the CSV files with a SQLite database that addresses
each of those problems:

- Three related tables (users, controls, assessments) linked by foreign
  keys, with foreign key enforcement turned on for every connection.
- CHECK, NOT NULL, and UNIQUE constraints so the database itself rejects
  bad data, even if application code is bypassed.
- Indexes on the columns the Risk Register and Priority Dashboard filter
  and sort by.
- Parameterized queries everywhere. Values never get concatenated into
  SQL text. The only strings placed into SQL text are fixed placeholders
  and entries from a hard-coded whitelist (see _ORDER_BY).
- SQLite transactions, so a write either completes or does not happen.

Scoring logic is not duplicated here. add_assessment() calls the same
functions the rest of the application uses (risk_calculator and ranking).
"""

import csv
import io
import os
import sqlite3
from contextlib import contextmanager

from ranking import calculate_weighted_priority_score
from risk_calculator import (
    calculate_priority_score,
    calculate_risk_score,
    get_priority_level,
)
from validators import (
    validate_category,
    validate_control_name,
    validate_score,
    validate_status,
)

DEFAULT_DB_FILE = "risk_tool.db"
SCHEMA_VERSION = 1

# Marker stored in place of a password hash for accounts that exist only
# because legacy data referred to them. It can never match a real hash,
# so those accounts cannot log in until a password is set.
DISABLED_PASSWORD_HASH = "!"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS controls (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL COLLATE NOCASE,
    category   TEXT    NOT NULL COLLATE NOCASE,
    benefit    TEXT,
    is_library INTEGER NOT NULL DEFAULT 0 CHECK (is_library IN (0, 1)),
    UNIQUE (name, category)
);

CREATE TABLE IF NOT EXISTS assessments (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    control_id              INTEGER NOT NULL UNIQUE
                            REFERENCES controls(id) ON DELETE RESTRICT,
    assessed_by             INTEGER NOT NULL
                            REFERENCES users(id) ON DELETE RESTRICT,
    likelihood              INTEGER NOT NULL CHECK (likelihood BETWEEN 1 AND 5),
    impact                  INTEGER NOT NULL CHECK (impact BETWEEN 1 AND 5),
    effort                  INTEGER NOT NULL CHECK (effort BETWEEN 1 AND 3),
    status                  TEXT    NOT NULL
                            CHECK (status IN ('Non-compliant', 'Partial', 'Compliant')),
    risk_score              INTEGER NOT NULL CHECK (risk_score BETWEEN 1 AND 25),
    priority_score          REAL    NOT NULL,
    weighted_priority_score REAL    NOT NULL,
    priority_level          TEXT    NOT NULL
                            CHECK (priority_level IN ('Critical', 'High', 'Medium', 'Low')),
    created_at              TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_assessments_priority_level
    ON assessments (priority_level);
CREATE INDEX IF NOT EXISTS idx_assessments_weighted_score
    ON assessments (weighted_priority_score DESC);
CREATE INDEX IF NOT EXISTS idx_assessments_assessed_by
    ON assessments (assessed_by);
CREATE INDEX IF NOT EXISTS idx_controls_category
    ON controls (category);
"""

# ORDER BY cannot take a bound parameter, so sort order is chosen from this
# fixed whitelist. Caller input selects a key; it is never placed in the SQL.
_ORDER_BY = {
    "id": "a.id ASC",
    "risk_desc": "a.risk_score DESC, a.id ASC",
    "weighted_desc": "a.weighted_priority_score DESC, a.risk_score DESC, c.name ASC",
}

_SELECT_ASSESSMENTS = """
SELECT c.name  AS control_name,
       c.category AS category,
       a.likelihood, a.impact, a.effort, a.status,
       a.risk_score, a.priority_score, a.weighted_priority_score,
       a.priority_level, u.username AS assessed_by
FROM assessments a
JOIN controls c ON c.id = a.control_id
JOIN users u    ON u.id = a.assessed_by
"""


class DuplicateAssessmentError(Exception):
    """Raised when a control (name + category) has already been assessed."""


def default_db_path() -> str:
    """The database file to use: RISK_TOOL_DB if set, otherwise risk_tool.db."""
    return os.environ.get("RISK_TOOL_DB", DEFAULT_DB_FILE)


def get_connection(db_path: str = None) -> sqlite3.Connection:
    """
    Opens a connection with foreign key enforcement on and makes sure the
    schema exists. SQLite leaves foreign keys off by default, and the
    setting applies per connection, so it must be set every time.
    """
    conn = sqlite3.connect(db_path or default_db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    init_db(conn)
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Creates tables and indexes if they do not exist. Safe to call repeatedly."""
    conn.executescript(SCHEMA)
    conn.execute(f"PRAGMA user_version = {int(SCHEMA_VERSION)}")
    conn.commit()


@contextmanager
def connection_scope(conn: sqlite3.Connection = None):
    """
    Yields the connection passed in, or opens (and closes) a default one.
    Lets functions work both inside a caller's transaction and on their own.
    """
    if conn is not None:
        yield conn
        return
    own = get_connection()
    try:
        yield own
    finally:
        own.close()


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

def count_users(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]


def create_user(conn: sqlite3.Connection, username: str, password_hash: str,
                commit: bool = True) -> bool:
    """Inserts a user. Returns False if the username is already taken."""
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
    except sqlite3.IntegrityError:
        return False
    if commit:
        conn.commit()
    return True


def get_password_hash(conn: sqlite3.Connection, username: str):
    row = conn.execute(
        "SELECT password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    return row["password_hash"] if row else None


def get_user_id(conn: sqlite3.Connection, username: str):
    row = conn.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()
    return row["id"] if row else None


def ensure_disabled_user(conn: sqlite3.Connection, username: str) -> int:
    """
    Returns the id of username, creating a login-disabled account if it
    does not exist. Used when imported data refers to a user who has no
    account here.
    """
    user_id = get_user_id(conn, username)
    if user_id is not None:
        return user_id
    create_user(conn, username, DISABLED_PASSWORD_HASH, commit=False)
    return get_user_id(conn, username)


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------

def read_csv_rows(path: str, required_columns=()) -> list:
    """
    Reads a CSV file into a list of dicts, tolerating the quirks of files
    saved by Excel: a leading byte order mark (BOM), Windows line endings,
    and semicolon or tab delimiters (Excel uses semicolons when the
    computer's regional settings use a decimal comma, as in Denmark).

    Raises ValueError if the file is empty or lacks a required column, so
    a wrong file fails loudly instead of being skipped row by row.
    """
    with open(path, newline="", encoding="utf-8-sig") as f:
        text = f.read()
    header_line = text.split("\n", 1)[0]
    delimiter = max(",;\t", key=header_line.count)
    reader = csv.DictReader(io.StringIO(text, newline=""), delimiter=delimiter)
    if not reader.fieldnames:
        raise ValueError(f"{path} is empty.")
    missing = [c for c in required_columns if c not in reader.fieldnames]
    if missing:
        raise ValueError(f"{path} is missing required column(s): {', '.join(missing)}")
    return list(reader)


def seed_controls_from_csv(conn: sqlite3.Connection, csv_path: str) -> int:
    """
    Loads the reference control library from controls.csv. Existing rows
    are updated, not duplicated, so this is safe to run on every start.
    Returns the number of rows read.
    """
    count = 0
    for row in read_csv_rows(csv_path, required_columns=("Control Name", "Category")):
        conn.execute(
            """
            INSERT INTO controls (name, category, benefit, is_library)
            VALUES (?, ?, ?, 1)
            ON CONFLICT (name, category)
            DO UPDATE SET benefit = excluded.benefit, is_library = 1
            """,
            (
                row["Control Name"].strip(),
                row["Category"].strip(),
                (row.get("Typical Benefit for Small Orgs") or "").strip(),
            ),
        )
        count += 1
    conn.commit()
    return count


def list_library_controls(conn: sqlite3.Connection) -> list:
    """Returns the reference library, using the column names the UI expects."""
    rows = conn.execute(
        """
        SELECT name, category, benefit FROM controls
        WHERE is_library = 1
        ORDER BY id
        """
    ).fetchall()
    return [
        {
            "Control Name": r["name"],
            "Category": r["category"],
            "Typical Benefit for Small Orgs": r["benefit"] or "",
        }
        for r in rows
    ]


def get_or_create_control(conn: sqlite3.Connection, name: str, category: str) -> int:
    """Returns the id of the control with this name and category, creating it if needed."""
    conn.execute(
        "INSERT OR IGNORE INTO controls (name, category, is_library) VALUES (?, ?, 0)",
        (name, category),
    )
    row = conn.execute(
        "SELECT id FROM controls WHERE name = ? AND category = ?", (name, category)
    ).fetchone()
    return row["id"]


# ---------------------------------------------------------------------------
# Assessments
# ---------------------------------------------------------------------------

def assessment_exists(conn: sqlite3.Connection, name: str, category: str) -> bool:
    """True if this control name and category already has an assessment (case-insensitive)."""
    row = conn.execute(
        """
        SELECT 1
        FROM assessments a
        JOIN controls c ON c.id = a.control_id
        WHERE c.name = ? AND c.category = ?
        """,
        (name, category),
    ).fetchone()
    return row is not None


def add_assessment(conn: sqlite3.Connection, control_name: str, category: str,
                   likelihood, impact, effort, status: str, username: str,
                   commit: bool = True) -> dict:
    """
    Validates and stores one assessment, computing every derived score
    with the application's existing scoring functions.

    Raises ValidationError for bad input and DuplicateAssessmentError if
    the control was already assessed. Nothing is written in either case.
    Returns the computed scores so the caller can show them.

    commit=False lets a caller (such as the migration script) group many
    inserts into a single transaction.
    """
    name = validate_control_name(control_name)
    category = validate_category(category)
    likelihood = validate_score(likelihood, 1, 5, "Likelihood")
    impact = validate_score(impact, 1, 5, "Impact")
    effort = validate_score(effort, 1, 3, "Effort")
    status = validate_status(status)

    user_id = get_user_id(conn, username)
    if user_id is None:
        raise ValueError(f"Unknown user: {username!r}")

    if assessment_exists(conn, name, category):
        raise DuplicateAssessmentError(
            f"'{name}' has already been assessed under '{category}'."
        )

    risk_score = calculate_risk_score(likelihood, impact)
    priority_score = round(calculate_priority_score(risk_score, effort), 2)
    weighted = calculate_weighted_priority_score(risk_score, effort, category, status)
    level = get_priority_level(risk_score)

    control_id = get_or_create_control(conn, name, category)
    try:
        conn.execute(
            """
            INSERT INTO assessments
                (control_id, assessed_by, likelihood, impact, effort, status,
                 risk_score, priority_score, weighted_priority_score, priority_level)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (control_id, user_id, likelihood, impact, effort, status,
             risk_score, priority_score, weighted, level),
        )
    except sqlite3.IntegrityError as exc:
        # The UNIQUE constraint is the backstop if two writers race past
        # the check above.
        raise DuplicateAssessmentError(
            f"'{name}' has already been assessed under '{category}'."
        ) from exc
    if commit:
        conn.commit()

    return {
        "risk_score": risk_score,
        "priority_score": priority_score,
        "weighted_priority_score": weighted,
        "priority_level": level,
    }


def list_assessments(conn: sqlite3.Connection, levels=None, categories=None,
                     order_by: str = "id") -> list:
    """
    Returns assessments as dicts keyed by the display column names used in
    the UI. levels and categories are optional filters: None means no
    filter, an empty list means match nothing.
    """
    if order_by not in _ORDER_BY:
        raise ValueError(f"order_by must be one of {sorted(_ORDER_BY)}")

    clauses, params = [], []
    for column, values in (("a.priority_level", levels), ("c.category", categories)):
        if values is None:
            continue
        values = list(values)
        if not values:
            return []
        placeholders = ",".join("?" for _ in values)  # only "?" characters
        clauses.append(f"{column} IN ({placeholders})")
        params.extend(values)

    sql = _SELECT_ASSESSMENTS
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY " + _ORDER_BY[order_by]  # whitelisted constant

    return [
        {
            "Control Name": r["control_name"],
            "Category": r["category"],
            "Likelihood": r["likelihood"],
            "Impact": r["impact"],
            "Effort": r["effort"],
            "Status": r["status"],
            "Risk Score": r["risk_score"],
            "Priority Score": r["priority_score"],
            "Weighted Priority Score": r["weighted_priority_score"],
            "Priority Level": r["priority_level"],
            "Assessed By": r["assessed_by"],
        }
        for r in conn.execute(sql, params).fetchall()
    ]


def clear_assessments(conn: sqlite3.Connection) -> None:
    """Deletes all assessments. Controls and users are kept."""
    conn.execute("DELETE FROM assessments")
    conn.commit()
