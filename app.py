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

Data is persisted to findings.csv in this folder (simple CSV storage
for V1). SQLite/database integration is reserved for the CS 499
enhancement, along with authentication, stronger validation, PDF report
generation, CIS/NIST mapping, charts, automated testing, and an
improved priority algorithm.
"""

import os

import pandas as pd
import streamlit as st

from risk_calculator import (
    calculate_priority_score,
    calculate_risk_score,
    get_priority_level,
)

DATA_FILE = "findings.csv"
CONTROLS_FILE = "controls.csv"
FINDINGS_COLUMNS = [
    "Control Name",
    "Category",
    "Likelihood",
    "Impact",
    "Effort",
    "Status",
    "Risk Score",
    "Priority Score",
    "Priority Level",
]

st.set_page_config(page_title="Cloud Security Risk Assessment Tool", layout="wide")


def load_findings() -> pd.DataFrame:
    if os.path.exists(DATA_FILE):
        return pd.read_csv(DATA_FILE)
    return pd.DataFrame(columns=FINDINGS_COLUMNS)


def save_findings(df: pd.DataFrame) -> None:
    df.to_csv(DATA_FILE, index=False)


@st.cache_data
def load_controls_library() -> pd.DataFrame:
    return pd.read_csv(CONTROLS_FILE)


if "findings" not in st.session_state:
    st.session_state.findings = load_findings()

controls_ref = load_controls_library()
categories = sorted(controls_ref["Category"].unique().tolist())

st.sidebar.title("🔒 Cloud Security Risk Tool")
st.sidebar.caption("For small orgs running Linux-based cloud infrastructure")
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
st.sidebar.metric("Controls Assessed So Far", len(st.session_state.findings))

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
        if not control_name or not str(control_name).strip():
            st.error("Please provide a control name before submitting.")
        else:
            risk_score = calculate_risk_score(likelihood, impact)
            priority_score = round(calculate_priority_score(risk_score, effort), 2)
            priority_level = get_priority_level(risk_score)

            new_row = pd.DataFrame(
                [
                    {
                        "Control Name": control_name,
                        "Category": category,
                        "Likelihood": likelihood,
                        "Impact": impact,
                        "Effort": effort,
                        "Status": status,
                        "Risk Score": risk_score,
                        "Priority Score": priority_score,
                        "Priority Level": priority_level,
                    }
                ]
            )
            st.session_state.findings = pd.concat(
                [st.session_state.findings, new_row], ignore_index=True
            )
            save_findings(st.session_state.findings)

            st.success(
                f"Added **{control_name}** — Risk Score: {risk_score} | "
                f"Priority Score: {priority_score} | Level: **{priority_level}**"
            )

    st.markdown("---")
    st.subheader("Recently Added")
    if len(st.session_state.findings) > 0:
        st.dataframe(st.session_state.findings.tail(5), use_container_width=True)
    else:
        st.caption("No assessments yet. Add your first control above.")

# ---------------------------------------------------------------------------
# PAGE 2: Risk Register
# ---------------------------------------------------------------------------
elif page.startswith("2"):
    st.title("Risk Register")
    df = st.session_state.findings

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

        filtered = df[
            df["Priority Level"].isin(level_filter) & df["Category"].isin(cat_filter)
        ].sort_values("Risk Score", ascending=False)

        st.dataframe(filtered, use_container_width=True)
        st.caption(f"Showing {len(filtered)} of {len(df)} total findings")

        st.download_button(
            "⬇ Download Risk Register (CSV)",
            filtered.to_csv(index=False),
            "risk_register.csv",
            "text/csv",
        )

        with st.expander("Danger zone"):
            if st.button("🗑 Clear all findings"):
                st.session_state.findings = pd.DataFrame(columns=FINDINGS_COLUMNS)
                save_findings(st.session_state.findings)
                st.rerun()

# ---------------------------------------------------------------------------
# PAGE 3: Priority Dashboard
# ---------------------------------------------------------------------------
elif page.startswith("3"):
    st.title("Priority Dashboard")
    df = st.session_state.findings

    if len(df) == 0:
        st.info("No findings recorded yet. Add assessments on the Form page first.")
    else:
        st.write(
            "Controls ranked by **Priority Score** (Risk Score ÷ Effort) — "
            "the highest security benefit for the lowest operational effort "
            "comes first."
        )

        ranked = df.sort_values("Priority Score", ascending=False).reset_index(drop=True)
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
                    "Priority Level",
                    "Status",
                ]
            ],
            use_container_width=True,
        )

        st.subheader("Top Quick Wins")
        for rank, row in ranked.head(5).iterrows():
            st.markdown(
                f"**#{rank}. {row['Control Name']}** — "
                f"Priority Score {row['Priority Score']} ({row['Priority Level']}), "
                f"Effort {row['Effort']}/3"
            )

        st.subheader("Priority Score by Control")
        chart_data = ranked.set_index("Control Name")["Priority Score"]
        st.bar_chart(chart_data)

# ---------------------------------------------------------------------------
# PAGE 4: Assessment Summary
# ---------------------------------------------------------------------------
else:
    st.title("Assessment Summary")
    df = st.session_state.findings

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
        top3 = df.sort_values("Priority Score", ascending=False).head(3)
        for _, row in top3.iterrows():
            st.markdown(
                f"- **{row['Control Name']}** ({row['Category']}) — "
                f"{row['Priority Level']} risk, Priority Score {row['Priority Score']}"
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
        st.dataframe(cat_summary, use_container_width=True)

        st.subheader("Priority Level Distribution")
        st.bar_chart(df["Priority Level"].value_counts())
