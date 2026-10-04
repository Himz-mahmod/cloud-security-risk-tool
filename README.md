# Cloud Security Risk Assessment Tool

**Version 4: Databases enhancement (CS 499 Milestone Four)**

## Milestone One Code Review

Watch the code review video here: https://youtu.be/olCzBg3x_1M

## What it is

A lightweight risk-prioritization tool built for **small organizations
running Linux-based cloud infrastructure**, not enterprise CSPM. It
answers one practical question: *with limited staff and budget, which
security control should we fix first?*

Instead of ranking findings by severity alone, it factors in
**implementation effort**, so the ranking reflects "highest security
benefit for lowest operational effort."

## How scoring works

- **Risk Score** = Likelihood (1-5) x Impact (1-5), range 1-25
- **Priority Score** = Risk Score / Implementation Effort (1-3)
- **Weighted Priority Score** = Priority Score adjusted by a category weight
  and a compliance-status multiplier (see `ranking.py`)
- **Priority Level**: Critical (20-25) / High (12-19) / Medium (6-11) / Low (1-5)

## Pages

1. **Security Assessment Form**: pick a control (from the built-in
   reference library or a custom entry), score it, and save it.
2. **Risk Register**: all findings in a filterable table, exportable to CSV.
3. **Priority Dashboard**: findings ranked by Weighted Priority Score, with a
   chart and a "top quick wins" list.
4. **Assessment Summary**: total controls, high-risk count, top priorities,
   and a category-wise rollup.

## Project structure

```
cloud-security-risk-tool/
├── app.py                      # Streamlit UI (login gate + all 4 pages)
├── database.py                 # SQLite schema, constraints, indexes, parameterized queries
├── migrate_csv_to_sqlite.py    # One-time import of findings.csv and users.json
├── benchmark_indexes.py        # Measures the effect of the indexes on generated data
├── auth.py                     # Password hashing + login/registration logic
├── validators.py               # Defensive input validation, independent of the UI
├── risk_calculator.py          # Risk Score, base Priority Score, priority level
├── ranking.py                  # Heap-based top-N ranking + weighted priority scoring
├── controls.csv                # Reference library of common controls, loaded into the database
├── requirements.txt
├── tests/                      # Automated pytest suite
│   ├── conftest.py             # Gives each test its own temporary database
│   ├── test_database.py
│   ├── test_migration.py
│   ├── test_app_flow.py        # Drives the real app: login, form, every page
│   ├── test_auth.py
│   ├── test_validators.py
│   ├── test_risk_calculator.py
│   └── test_ranking.py
├── .github/workflows/tests.yml # CI: runs the test suite on every push/PR
└── README.md
```

## The database

Data lives in a SQLite file, `risk_tool.db`, created automatically on first
run. Set the `RISK_TOOL_DB` environment variable to use a different file.

| Table | Purpose |
|---|---|
| `users` | Accounts. Passwords are stored as salted PBKDF2 hashes. Usernames are case-insensitive. |
| `controls` | Each control (name + category). `is_library` marks the reference library loaded from `controls.csv`. |
| `assessments` | One scored assessment per control, linked to `controls` and `users` by foreign keys. |

What the database enforces on its own, even if application code is bypassed:

- Foreign keys (turned on for every connection): an assessment cannot point
  at a control or user that does not exist, and a control or user with
  assessments cannot be deleted.
- `CHECK` constraints on likelihood (1-5), impact (1-5), effort (1-3),
  status, risk score, and priority level.
- `UNIQUE` on control name + category (case-insensitive) and on the control
  of each assessment, so a control cannot be assessed twice.

All queries use bound parameters. The one thing a parameter cannot do is
choose a sort order, so `list_assessments` picks `ORDER BY` from a fixed
whitelist instead of using caller input.

Indexes: `weighted_priority_score` (for top-N queries), `priority_level`,
`controls.category`, and `assessed_by`. Run `python benchmark_indexes.py` to
measure them. On 50,000 generated rows, the top-5 query ran roughly a
thousand times faster with the index. The `priority_level` filter gained only
about 2 to 3 times, because that column has just four distinct values.

## Migrating data from the CSV versions

If you have a `findings.csv` (and optionally a `users.json` from the
Milestone Two version) from earlier versions:

```bash
python migrate_csv_to_sqlite.py
```

The whole import runs in one transaction, so a failure leaves the database
unchanged. Scores are recomputed rather than copied. Invalid and duplicate
rows are skipped and counted. Running it twice is safe. Accounts that
`findings.csv` mentions but that have no login get a disabled placeholder
account.

## Logging in

On first run, with no users in the database, a default account is created:

- **Username:** `admin`
- **Password:** `changeme123`

This exists only so the app is usable right after cloning. In any real
deployment, change it immediately or register a new account with
`auth.register_user()`.

## Running the tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

A GitHub Actions workflow (`.github/workflows/tests.yml`) runs the same
test suite on every push and pull request to `main`.

## Running it locally

```bash
# from inside the cloud-security-risk-tool folder
python -m venv venv
# Mac/Linux:  source venv/bin/activate
# Windows:    venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

This opens the app in your browser at `http://localhost:8501`.

## Enhancement status

**Software Design and Engineering (Milestone Two)**
- Salted, hashed passwords and a login gate
- UI-independent input validation and duplicate detection
- Automated pytest suite and GitHub Actions CI

**Algorithms and Data Structures (Milestone Three)**
- Bounded-heap top-N retrieval, O(m log n) instead of a full sort
- Weighted priority score using category and compliance status

**Databases (Milestone Four)**
- SQLite replaces the CSV files, with related tables and foreign keys
- Constraints enforced by the database, plus indexes
- Parameterized queries and a whitelisted sort order
- Transactional, repeatable migration of the old CSV and JSON data
- End-to-end tests of the running app

**Still planned**
- PDF report generation
- CIS / NIST control mapping
- A way to edit or delete a single assessment
