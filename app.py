"""
app.py

Cloud Security Risk Assessment Tool - Version 1

A lightweight risk-prioritization tool for small organizations running
Linux-based cloud infrastructure. Unlike enterprise CSPM platforms, this
tool ranks controls by "highest security benefit for lowest operational
effort" -- useful when you have limited staff/budget and need to know
what to fix first.

Pages:
    1. Security Assessment Form  -- score a control
    2. Risk Register             -- table of all findings
    3. Priority Dashboard        -- ranked by priority score
    4. Assessment Summary        -- rollup stats

Data is stored in a SQLite database (risk_tool.db) with related users,
controls, and assessments tables. See database.py for the schema,
constraints, and indexes, and migrate_csv_to_sqlite.py to bring over data
from the earlier CSV-based versions.
"""

import os
from contextlib import closing

import pandas as pd
import streamlit as st

from auth import authenticate
from database import (
    DuplicateAssessmentError,
    add_assessment,
    clear_assessments,
    default_db_path,
    get_connection,
    list_assessments,
    list_library_controls,
    seed_controls_from_csv,
)
from ranking import get_top_priority_controls
from validators import ValidationError

CONTROLS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "controls.csv")
FINDINGS_COLUMNS = [
    "Control Name",
    "Category",
    "Likelihood",
    "Impact",
    "Effort",
    "Status",
    "Risk Score",
    "Priority Score",
    "Weighted Priority Score",
    "Priority Level",
    "Assessed By",
]

st.set_page_config(page_title="Cloud Security Risk Assessment Tool", layout="wide")


# ---------------------------------------------------------------------------
# Authentication gate -- nothing below this runs until the user logs in.
# ---------------------------------------------------------------------------
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    st.title("Cloud Security Risk Tool -- Login")
    st.caption(
        "Default account for first run: admin / changeme123 "
        "(change this immediately in any real deployment)."
    )
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        login_submitted = st.form_submit_button("Log In")

    if login_submitted:
        if authenticate(username, password):
            st.session_state.authenticated = True
            st.session_state.username = username
            st.rerun()
        else:
            st.error("Invalid username or password.")

    st.stop()  # Nothing past this point renders for an unauthenticated user.


@st.cache_resource
def bootstrap_database(db_path: str) -> bool:
    """Loads the reference control library once per server start (per database file)."""
    with closing(get_connection(db_path)) as conn:
        seed_controls_from_csv(conn, CONTROLS_FILE)
    return True


def load_findings(levels=None, categories=None, order_by="id") -> pd.DataFrame:
    """Reads assessments from the database. Filtering and ordering happen in SQL."""
    with closing(get_connection()) as conn:
        rows = list_assessments(conn, levels=levels, categories=categories, order_by=order_by)
    return pd.DataFrame(rows, columns=FINDINGS_COLUMNS)


def load_controls_library() -> pd.DataFrame:
    with closing(get_connection()) as conn:
        rows = list_library_controls(conn)
    return pd.DataFrame(
        rows, columns=["Control Name", "Category", "Typical Benefit for Small Orgs"]
    )


bootstrap_database(default_db_path())
findings_df = load_findings()
controls_ref = load_controls_library()
categories = sorted(controls_ref["Category"].unique().tolist())

st.sidebar.title("🔒 Cloud Security Risk Tool")
st.sidebar.caption("For small orgs running Linux-based cloud infrastructure")
st.sidebar.markdown(f"**Logged in as:** {st.session_state.username}")
if st.sidebar.button("Log Out"):
    st.session_state.authenticated = False
    st.session_state.pop("username", None)
    st.rerun()
st.sidebar.markdown("---")
page = st.sidebar.radio(
    "Navigate",
    [
        "1. Security Assessment Form",
        "2. Risk Register",
        "3. Priority Dashboard",
        "4. Assessment Summary",
    ],
)
st.sidebar.markdown("---")
st.sidebar.metric("Controls Assessed So Far", len(findings_df))

# ---------------------------------------------------------------------------
# PAGE 1: Security Assessment Form
# ---------------------------------------------------------------------------
if page.startswith("1"):
    st.title("Security Assessment Form")
    st.write(
        "Score a control on likelihood, impact, and implementation effort. "
        "The tool calculates a risk score and a priority score so you know "
        "what to fix first."
    )

    control_source = st.radio(
        "Control name", ["Choose from reference library", "Enter a custom control"]
    )

    if control_source == "Choose from reference library":
        control_name = st.selectbox("Select a control", controls_ref["Control Name"].tolist())
        matched = controls_ref.loc[controls_ref["Control Name"] == control_name].iloc[0]
        default_category = matched["Category"]
        st.info(f"💡 {matched['Typical Benefit for Small Orgs']}")
    else:
        control_name = st.text_input("Custom control name")
        default_category = categories[0] if categories else "Other"

    with st.form("assessment_form", clear_on_submit=True):
        col1, col2 = st.columns(2)

        with col1:
            category_options = categories + ["Other"]
            default_index = (
                category_options.index(default_category)
                if default_category in category_options
                else 0
            )
            category = st.selectbox("Category", category_options, index=default_index)
            status = st.selectbox(
                "Current Status", ["Non-compliant", "Partial", "Compliant"]
            )

        with col2:
            likelihood = st.slider("Likelihood (1 = rare, 5 = almost certain)", 1, 5, 3)
            impact = st.slider("Impact (1 = negligible, 5 = severe)", 1, 5, 3)
            effort = st.slider(
                "Implementation Effort (1 = quick win, 3 = major project)", 1, 3, 2
            )

        submitted = st.form_submit_button("Add Assessment")

    if submitted:
        try:
            # add_assessment validates every field, rejects duplicates, and
            # computes the scores, so the same rules apply no matter where
            # data comes from. The database enforces them again with
            # constraints.
            with closing(get_connection()) as conn:
                result = add_assessment(
                    conn,
                    control_name,
                    category,
                    likelihood,
                    impact,
                    effort,
                    status,
                    st.session_state.username,
                )
        except ValidationError as e:
            st.error(str(e))
        except DuplicateAssessmentError:
            st.warning(
                f"'{str(control_name).strip()}' has already been assessed under "
                f"'{category}'. Duplicate entries are not allowed."
            )
        except ValueError:
            st.error("Your account no longer exists. Log out and log in again.")
        else:
            findings_df = load_findings()
            st.success(
                f"Added **{str(control_name).strip()}**: "
                f"Risk Score {result['risk_score']} | "
                f"Priority Score {result['priority_score']} "
                f"(Weighted: {result['weighted_priority_score']}) | "
                f"Level: **{result['priority_level']}**"
            )

    st.markdown("---")
    st.subheader("Recently Added")
    if len(findings_df) > 0:
        st.dataframe(findings_df.tail(5))
    else:
        st.caption("No assessments yet. Add your first control above.")

# ---------------------------------------------------------------------------
# PAGE 2: Risk Register
# ---------------------------------------------------------------------------
elif page.startswith("2"):
    st.title("Risk Register")
    df = findings_df

    if len(df) == 0:
        st.info("No findings recorded yet. Add assessments on the Form page first.")
    else:
        col1, col2 = st.columns(2)
        with col1:
            level_filter = st.multiselect(
                "Filter by Priority Level",
                options=sorted(df["Priority Level"].unique()),
                default=sorted(df["Priority Level"].unique()),
            )
        with col2:
            cat_filter = st.multiselect(
                "Filter by Category",
                options=sorted(df["Category"].unique()),
                default=sorted(df["Category"].unique()),
            )

        filtered = load_findings(
            levels=level_filter, categories=cat_filter, order_by="risk_desc"
        )

        st.dataframe(filtered)
        st.caption(f"Showing {len(filtered)} of {len(df)} total findings")

        st.download_button(
            "⬇ Download Risk Register (CSV)",
            filtered.to_csv(index=False),
            "risk_register.csv",
            "text/csv",
        )

        with st.expander("Danger zone"):
            if st.button("🗑 Clear all findings"):
                with closing(get_connection()) as conn:
                    clear_assessments(conn)
                st.rerun()

# ---------------------------------------------------------------------------
# PAGE 3: Priority Dashboard
# ---------------------------------------------------------------------------
elif page.startswith("3"):
    st.title("Priority Dashboard")
    df = findings_df

    if len(df) == 0:
        st.info("No findings recorded yet. Add assessments on the Form page first.")
    else:
        st.write(
            "Controls ranked by **Weighted Priority Score**, a category "
            "and compliance-status-aware version of Risk Score ÷ Effort, "
            "so the highest real-world security benefit for the lowest "
            "operational effort comes first."
        )

        ranked = df.sort_values(
            "Weighted Priority Score", ascending=False
        ).reset_index(drop=True)
        ranked.index = ranked.index + 1
        ranked.index.name = "Rank"
        st.dataframe(
            ranked[
                [
                    "Control Name",
                    "Category",
                    "Risk Score",
                    "Effort",
                    "Priority Score",
                    "Weighted Priority Score",
                    "Priority Level",
                    "Status",
                ]
            ]
        )

        st.subheader("Top Quick Wins")
        st.caption(
            "Computed with a bounded heap (O(m log n)) instead of sorting "
            "the full table, since only the top few results are needed here."
        )
        top_wins = get_top_priority_controls(
            df.to_dict("records"), n=5, score_field="Weighted Priority Score"
        )
        for rank, row in enumerate(top_wins, start=1):
            st.markdown(
                f"**#{rank}. {row['Control Name']}**: "
                f"Weighted Priority Score {row['Weighted Priority Score']} "
                f"({row['Priority Level']}), Effort {row['Effort']}/3"
            )

        st.subheader("Weighted Priority Score by Control")
        chart_data = ranked.set_index("Control Name")["Weighted Priority Score"]
        st.bar_chart(chart_data)


# ---------------------------------------------------------------------------
# PAGE 4: Assessment Summary
# ---------------------------------------------------------------------------
else:
    st.title("Assessment Summary")
    df = findings_df

    if len(df) == 0:
        st.info("No findings recorded yet. Add assessments on the Form page first.")
    else:
        total = len(df)
        high_critical = len(df[df["Priority Level"].isin(["Critical", "High"])])
        non_compliant = len(df[df["Status"] == "Non-compliant"])
        avg_risk = round(df["Risk Score"].mean(), 1)

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Controls Assessed", total)
        c2.metric("High/Critical Findings", high_critical)
        c3.metric("Non-Compliant Controls", non_compliant)
        c4.metric("Average Risk Score", avg_risk)

        st.subheader("Top 3 Priorities")
        top3 = get_top_priority_controls(
            df.to_dict("records"), n=3, score_field="Weighted Priority Score"
        )
        for row in top3:
            st.markdown(
                f"- **{row['Control Name']}** ({row['Category']}): "
                f"{row['Priority Level']} risk, Weighted Priority Score "
                f"{row['Weighted Priority Score']}"
            )

        st.subheader("Category-wise Summary")
        cat_summary = (
            df.groupby("Category")
            .agg(
                Controls=("Control Name", "count"),
                Avg_Risk_Score=("Risk Score", "mean"),
                High_Critical_Count=(
                    "Priority Level",
                    lambda s: s.isin(["Critical", "High"]).sum(),
                ),
            )
            .round(1)
        )
        st.dataframe(cat_summary)

        st.subheader("Priority Level Distribution")
        st.bar_chart(df["Priority Level"].value_counts())
