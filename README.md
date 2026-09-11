# Cloud Security Risk Assessment Tool (Version 1)

A lightweight risk-prioritization tool built for **small organizations
running Linux-based cloud infrastructure** — not enterprise CSPM. It
answers one practical question: *with limited staff and budget, which
security control should we fix first?*

Instead of ranking findings by severity alone, it factors in
**implementation effort**, so the ranking reflects "highest security
benefit for lowest operational effort."

## How scoring works

- **Risk Score** = Likelihood (1–5) × Impact (1–5) → range 1–25
- **Priority Score** = Risk Score ÷ Implementation Effort (1–3)
- **Priority Level**: Critical (20–25) / High (12–19) / Medium (6–11) / Low (1–5)

## Pages

1. **Security Assessment Form** — pick a control (from the built-in
   reference library or a custom entry), score it, and save it.
2. **Risk Register** — all findings in a filterable table, exportable
   to CSV.
3. **Priority Dashboard** — findings ranked by Priority Score, with a
   chart and a "top quick wins" list.
4. **Assessment Summary** — total controls, high-risk count, top
   priorities, and a category-wise rollup.

## Project structure

```
cloud-security-risk-tool/
├── app.py               # Streamlit UI (all 4 pages)
├── risk_calculator.py   # Scoring logic, unit-testable and separate from UI
├── controls.csv         # Reference library of common controls for small-org Linux/cloud setups
├── requirements.txt
└── README.md
```

Assessment data you enter is saved to a `findings.csv` file that is
created automatically the first time you submit the form.

## Running it locally (Mac)

```bash
# from inside the cloud-security-risk-tool folder
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

This opens the app in your browser at `http://localhost:8501`.

## Scope note (Version 1)

This version is deliberately simple, per the CS 3XX capstone baseline.
The following are reserved for the **CS 499 enhancement**:

- SQLite/database integration (replacing the CSV file)
- User authentication
- Stronger input validation
- PDF report generation
- CIS / NIST control mapping
- Additional charts/visualizations
- Automated tests
- An improved, more sophisticated priority algorithm
