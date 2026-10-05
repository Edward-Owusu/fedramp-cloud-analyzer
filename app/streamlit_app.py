"""Interactive dashboard for the FedRAMP Cloud Analyzer.

Run locally:   streamlit run app/streamlit_app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cloud_check import __version__, assess, parse_inventory  # noqa: E402
from cloud_check.checks import DataError  # noqa: E402
from cloud_check.engine import BASELINES  # noqa: E402
from cloud_check.reporting import DISCLAIMER, STATUS_TEXT, TYPE_LABEL, to_csv, to_html, to_json, to_markdown  # noqa: E402

S = ROOT / "samples"
SAMPLES = {
    "SaaS startup preparing for FedRAMP (fictional)": S / "lakeside_route_software_aws.json",
    "SaaS company in readiness review (fictional)": S / "harborview_data_systems_aws.json",
}
STATUS_STYLE = {"Critical gaps": ":red[**Critical gaps**]", "Gaps": ":orange[**Gaps**]",
                "Pass": ":green[**Pass**]", "No data": ":gray[**No data**]"}
ICON = {"Identity": "🪪", "Logging and monitoring": "📜", "Network": "🌐", "Storage": "🪣",
        "Databases": "🗄️", "Compute": "🖥️", "Encryption keys": "🔑"}
SEV = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}

st.set_page_config(page_title="FedRAMP Cloud Analyzer", page_icon="☁️", layout="wide")
st.title("☁️ FedRAMP readiness pre-check")
st.write("Check a cloud environment's configuration against FedRAMP-aligned NIST SP 800-53 controls before "
         "paying for a formal assessment. Built for small cloud and SaaS providers preparing to serve federal agencies.")

with st.sidebar:
    st.header("1. Choose data")
    source = st.radio("Inventory", ["Use a sample", "Upload my own JSON"], label_visibility="collapsed")
    text = None
    if source == "Use a sample":
        text = SAMPLES[st.selectbox("Sample company", list(SAMPLES))].read_text(encoding="utf-8")
    else:
        up = st.file_uploader("Cloud inventory (.json)", type=["json"])
        st.download_button("Inventory template", (S / "inventory_template.json").read_bytes(),
                           "inventory_template.json", "application/json")
        if up:
            text = up.getvalue().decode("utf-8-sig", errors="replace")
    st.header("2. Choose baseline")
    baseline = st.selectbox("NIST SP 800-53 baseline", BASELINES, index=1, format_func=str.title)
    st.caption(f"cloud_check {__version__}. Runs entirely in this session; uploaded files are not stored.")

if text is None:
    st.info("Upload a cloud inventory in the sidebar, or switch to a sample, to see results.")
    st.stop()
try:
    inv = parse_inventory(text)
except DataError as exc:
    st.error(f"The file could not be read. {exc} Fix the file and upload it again.")
    st.stop()

r = assess(inv, baseline)
st.subheader(r.organization)
if inv.get("description"):
    st.caption(inv["description"])

m1, m2, m3, m4 = st.columns(4)
m1.metric(f"Readiness: {r.readiness_label}", "n/a" if r.readiness is None else f"{r.readiness:.0f} / 100")
m2.metric("Critical findings", sum(1 for f in r.findings if f.severity == "critical"))
m3.metric("Total findings", len(r.findings))
m4.metric("Resources checked", r.resources)

st.markdown("### Service areas")
by_cat = r.by_category()
cols = st.columns(4)
for i, c in enumerate(r.categories):
    with cols[i % 4].container(border=True):
        st.markdown(f"#### {ICON.get(c.category, '')} {c.category}")
        st.markdown(STATUS_STYLE.get(c.status, c.status))
        st.caption(f"{c.checks_failed} of {c.checks} checks failing · {c.resources_failing} resource(s) affected")
        fs = by_cat.get(c.category, [])
        if fs:
            with st.expander(f"View {len(fs)} finding{'s' if len(fs) != 1 else ''}"):
                for f in fs:
                    st.markdown(f"{SEV[f.severity]} **{f.check_id}** {f.title}  \n`{f.resource}`: {f.detail}  \n"
                                f"*Fix:* {f.remediation}  \n*Controls:* {', '.join(f.controls)}")

tab_r, tab_c = st.tabs(["Findings by resource", "All checks"])
with tab_r:
    if r.findings:
        st.dataframe(pd.DataFrame([{"Severity": f.severity.title(), "Resource": f.resource,
                                    "Type": TYPE_LABEL.get(f.resource_type, f.resource_type), "Area": f.category,
                                    "Issue": f.title, "Detail": f.detail, "Controls": ", ".join(f.controls)}
                                   for f in r.findings]), hide_index=True)
    else:
        st.success("No findings.")
with tab_c:
    st.dataframe(pd.DataFrame([{"Check": s.check_id, "Area": s.category, "Title": s.title,
                                "Controls": ", ".join(s.controls), "Severity": s.severity.title(),
                                "Result": STATUS_TEXT[s.status], "Failing": f"{s.failed} of {s.in_scope}"}
                               for s in r.checks]), hide_index=True)

st.markdown("### Download the report")
d1, d2, d3, d4 = st.columns(4)
d1.download_button("HTML report", to_html(r), "fedramp_precheck.html", "text/html")
d2.download_button("Markdown", to_markdown(r), "fedramp_precheck.md", "text/markdown")
d3.download_button("CSV findings", to_csv(r), "fedramp_findings.csv", "text/csv")
d4.download_button("JSON results", to_json(r), "fedramp_results.json", "application/json")
st.caption(DISCLAIMER)
