"""Interactive dashboard for the FedRAMP Cloud Analyzer.

Run locally:   streamlit run app/streamlit_app.py

Layout: no sidebar. The main screen is a service map of the cloud environment: each service area
(identity, network, storage and so on) is a tile coloured by status, and the selected area opens
its findings grouped by resource.
"""

from __future__ import annotations

import sys
from html import escape
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import ui  # noqa: E402
from cloud_check import __version__, assess, parse_inventory  # noqa: E402
from cloud_check.checks import DataError  # noqa: E402
from cloud_check.engine import BASELINES  # noqa: E402
from cloud_check.reporting import DISCLAIMER, STATUS_TEXT, TYPE_LABEL, to_csv, to_html, to_json, to_markdown  # noqa: E402

S = ROOT / "samples"
SAMPLES = {
    "SaaS startup preparing for FedRAMP (fictional)": S / "lakeside_route_software_aws.json",
    "SaaS company in readiness review (fictional)": S / "harborview_data_systems_aws.json",
}
STATUS_COLOR = {"Critical gaps": "#B42318", "Gaps": "#D97706", "Pass": "#15803D", "No data": "#94A3B8"}
ICON = {"Identity": "🪪", "Logging and monitoring": "📜", "Network": "🌐", "Storage": "🪣",
        "Databases": "🗄️", "Compute": "🖥️", "Encryption keys": "🔑"}

PAL = ui.Palette(accent="#0369A1", band="#0B2537", band_text="#FFFFFF", band_sub="#A9C6DA",
                 card="#FFFFFF", line="#D3E4F0", ink="#0B2537", muted="#4F6B80")
ui.setup("FedRAMP readiness pre-check", "Cloud configuration · FedRAMP-aligned NIST SP 800-53",
         "Check a cloud environment's configuration against FedRAMP-aligned NIST SP 800-53 controls before paying "
         "for a formal assessment. Built for small cloud and SaaS providers preparing to serve federal agencies.",
         "☁️", PAL)

# ---- Top row: data and baseline ----------------------------------------------------------------------
t1, t2, t3 = st.columns([1.6, 2.8, 1.2], vertical_alignment="top")
text = None
with t1:
    st.caption("Cloud inventory")
    source = ui.choose("Inventory", ["Use a sample", "Upload my own JSON"], key="source", format_func=ui.source_label)
with t2:
    if source == "Use a sample":
        st.caption("Sample company")
        text = SAMPLES[st.selectbox("Sample company", list(SAMPLES), label_visibility="collapsed")].read_text(
            encoding="utf-8")
    else:
        st.caption("Your cloud inventory (.json)")
        up = st.file_uploader("Cloud inventory (.json)", type=["json"], label_visibility="collapsed")
        if up:
            text = up.getvalue().decode("utf-8-sig", errors="replace")
with t3:
    st.caption("NIST SP 800-53 baseline")
    baseline = st.selectbox("NIST SP 800-53 baseline", BASELINES, index=1, format_func=str.title,
                            label_visibility="collapsed")
if source != "Use a sample":
    st.download_button("Download the inventory template", (S / "inventory_template.json").read_bytes(),
                       "inventory_template.json", "application/json")

if text is None:
    st.info("Upload a cloud inventory above, or switch to a sample, to see the service map.")
    ui.footer("cloud_check", __version__, "fedramp-cloud-analyzer", DISCLAIMER)
    st.stop()
try:
    inv = parse_inventory(text)
except DataError as exc:
    st.error(f"The file could not be read. {exc} Fix the file and upload it again.")
    st.stop()

r = assess(inv, baseline)
by_cat = r.by_category()
st.markdown(f"<div class='g-sec'>{escape(r.organization)}</div>", unsafe_allow_html=True)
st.caption((inv.get("description") or "") + f" · {r.provider} · {r.baseline.title()} baseline")
g, m = st.columns([1, 3], vertical_alignment="center")
with g:
    score = r.readiness or 0
    color = ("#15803D" if score >= 90 else "#65A30D" if score >= 75 else "#D97706" if score >= 50 else "#B42318")
    st.markdown(ui.gauge(score, r.readiness_label, color if r.readiness is not None else "#94A3B8", PAL,
                         caption="Readiness, higher is better"), unsafe_allow_html=True)
with m:
    ui.tiles([(sum(1 for f in r.findings if f.severity == "critical"), "Critical findings", "#B42318"),
              (len(r.findings), "Total findings", "#D97706"),
              (r.resources, "Resources checked"),
              (sum(1 for c in r.categories if c.status == "Pass"), f"of {len(r.categories)} service areas pass",
               "#15803D")], PAL)

view = ui.choose("View", ["Service map", "Findings by resource", "All checks"], key="view")

if view == "Service map":
    ui.section("Service map", "Each tile is one area of the cloud environment, coloured by its worst result. "
               "Pick an area below to see what is failing and where.")
    tiles = []
    for c in r.categories:
        col = STATUS_COLOR.get(c.status, "#94A3B8")
        tiles.append(f"<div style='background:{col};color:#fff;border-radius:12px;padding:12px 14px'>"
                     f"<div style='font-size:22px'>{ICON.get(c.category, '')}</div>"
                     f"<div style='font-weight:700;font-size:15px'>{escape(c.category)}</div>"
                     f"<div style='font-size:12.5px;opacity:.92'>{escape(c.status)} · {c.checks_failed} of {c.checks} "
                     f"checks failing · {c.resources_failing} resource(s)</div></div>")
    st.markdown("<div style='display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:10px;"
                f"margin-bottom:12px'>{''.join(tiles)}</div>", unsafe_allow_html=True)
    cats = [c.category for c in r.categories]
    worst = next((c.category for c in r.categories if c.status == "Critical gaps"), cats[0] if cats else None)
    area = ui.choose("Service area", cats, key="area", default=worst,
                     format_func=lambda c: f"{ICON.get(c, '')} {c}")
    fs = by_cat.get(area, [])
    if not fs:
        st.success(f"No findings in {area}.")
    resources: dict[str, list] = {}
    for f in fs:
        resources.setdefault(f.resource, []).append(f)
    cols = st.columns(2)
    for i, (res, items) in enumerate(resources.items()):
        rows = "".join(f"<div class='d'>{ui.sev_pill(f.severity)}<b>{escape(f.check_id)}</b> {escape(f.title)}. "
                       f"<span class='s'>{escape(f.detail)}</span><div class='f'>Fix: {escape(f.remediation)} "
                       f"<span class='s'>({escape(', '.join(f.controls))})</span></div></div>" for f in items)
        with cols[i % 2]:
            ui.card(f"<div class='h'><code>{escape(res)}</code></div><div class='s'>"
                    f"{escape(TYPE_LABEL.get(items[0].resource_type, items[0].resource_type))} · "
                    f"{len(items)} issue(s)</div>", rows, accent=ui.SEV_COLORS[items[0].severity])

elif view == "Findings by resource":
    if r.findings:
        st.dataframe(pd.DataFrame([{"Severity": f.severity.title(), "Resource": f.resource,
                                    "Type": TYPE_LABEL.get(f.resource_type, f.resource_type), "Area": f.category,
                                    "Issue": f.title, "Detail": f.detail, "Controls": ", ".join(f.controls)}
                                   for f in r.findings]), hide_index=True, use_container_width=True)
    else:
        st.success("No findings.")
else:
    st.dataframe(pd.DataFrame([{"Check": s.check_id, "Area": s.category, "Title": s.title,
                                "Controls": ", ".join(s.controls), "Severity": s.severity.title(),
                                "Result": STATUS_TEXT[s.status], "Failing": f"{s.failed} of {s.in_scope}"}
                               for s in r.checks]), hide_index=True, use_container_width=True)

ui.downloads([("HTML report", to_html(r), "fedramp_precheck.html", "text/html"),
              ("Markdown", to_markdown(r), "fedramp_precheck.md", "text/markdown"),
              ("CSV findings", to_csv(r), "fedramp_findings.csv", "text/csv"),
              ("JSON results", to_json(r), "fedramp_results.json", "application/json")])
ui.footer("cloud_check", __version__, "fedramp-cloud-analyzer", DISCLAIMER)
