"""Write results as JSON, CSV, Markdown, or a self-contained HTML report with service cards."""

from __future__ import annotations

import csv
import io
import json
from html import escape

from .checks import FAIL, NOT_APPLICABLE, NOT_ASSESSED, PASS
from .engine import Result

DISCLAIMER = (
    "This is an automated readiness pre-check of the configuration data supplied. It is not a FedRAMP "
    "assessment or authorization, does not replace a Third Party Assessment Organization (3PAO), and covers "
    "only the configuration checks listed. Baseline membership follows NIST SP 800-53B; verify against the "
    "official FedRAMP baseline."
)
STATUS_TEXT = {PASS: "Pass", FAIL: "Fail", NOT_ASSESSED: "Not assessed", NOT_APPLICABLE: "Not applicable"}
TYPE_LABEL = {"storage_bucket": "Storage bucket", "security_group": "Security group", "compute_instance": "Server",
              "database": "Database", "load_balancer": "Load balancer", "iam_user": "User", "kms_key": "Key",
              "account": "Account"}


def to_json(r: Result) -> str:
    return json.dumps(r.to_dict(), indent=2, default=str)


def to_csv(r: Result) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["category", "check_id", "title", "severity", "controls", "resource", "resource_type", "detail", "remediation"])
    for f in r.findings:
        w.writerow([f.category, f.check_id, f.title, f.severity, "; ".join(f.controls), f.resource,
                    f.resource_type, f.detail, f.remediation])
    return buf.getvalue()


def to_markdown(r: Result) -> str:
    score = "n/a" if r.readiness is None else f"{r.readiness:.0f}/100"
    lines = [f"# FedRAMP readiness pre-check: {r.organization}", "",
             f"Provider: {r.provider} | NIST SP 800-53 {r.baseline} baseline | {r.resources} resources | Generated {r.generated_at}",
             "", f"- Readiness: **{score} ({r.readiness_label})**",
             f"- Findings: **{len(r.findings)}**, of which critical: **{sum(1 for f in r.findings if f.severity == 'critical')}**",
             "", "## Service areas", "", "| Area | Status | Checks failing | Resources affected |", "|---|---|---|---|"]
    for c in r.categories:
        lines.append(f"| {c.category} | {c.status} | {c.checks_failed} of {c.checks} | {c.resources_failing} |")
    lines += ["", "## Findings", ""]
    for cat, fs in r.by_category().items():
        lines += [f"### {cat}", ""]
        for f in fs:
            lines.append(f"- **[{f.severity.upper()}] {f.check_id}** {f.title}: `{f.resource}`. {f.detail} "
                         f"_Controls: {', '.join(f.controls)}. Fix: {f.remediation}_")
        lines.append("")
    if not r.findings:
        lines.append("No findings.")
    lines += ["", f"_{DISCLAIMER}_", ""]
    return "\n".join(lines)


_CSS = """
:root{--ink:#0b2537;--muted:#4a6275;--line:#cfe0ec;--paper:#fff;--wash:#f3f8fc;--sky:#0369a1;--sky2:#e0f0fa;
--crit:#b42318;--gap:#b45309;--ok:#047857;--na:#64748b}
*{box-sizing:border-box}
body{margin:0;background:var(--wash);color:var(--ink);
font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
header{background:linear-gradient(135deg,#0369a1,#0ea5e9);color:#fff}
header .inner{max-width:1040px;margin:0 auto;padding:36px 24px 30px}
header h1{margin:0 0 6px;font-size:28px;font-weight:700;letter-spacing:-.01em}
header p{margin:0;opacity:.9}
.score{display:flex;gap:28px;flex-wrap:wrap;margin-top:22px;align-items:flex-end}
.score .big{font-size:52px;font-weight:800;line-height:1}
.score .big small{font-size:18px;font-weight:600;opacity:.85}
.score .lbl{font-size:13px;opacity:.9}
main{max-width:1040px;margin:0 auto;padding:28px 24px 64px}
h2{font-size:20px;margin:36px 0 14px;color:var(--sky)}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:14px}
.card{background:var(--paper);border:1px solid var(--line);border-radius:10px;padding:16px;border-top:5px solid var(--na)}
.card h3{margin:0 0 8px;font-size:16px}
.card .pill{display:inline-block;font-size:12px;font-weight:700;padding:2px 10px;border-radius:999px;color:#fff;background:var(--na)}
.card p{margin:8px 0 0;color:var(--muted);font-size:13px}
.c-Pass{border-top-color:var(--ok)}.c-Pass .pill{background:var(--ok)}
.c-Gaps{border-top-color:var(--gap)}.c-Gaps .pill{background:var(--gap)}
.c-Critical-gaps{border-top-color:var(--crit)}.c-Critical-gaps .pill{background:var(--crit)}
section.area{background:var(--paper);border:1px solid var(--line);border-radius:10px;padding:6px 18px 12px;margin:14px 0}
section.area h3{color:var(--ink);margin:12px 0 4px}
.f{border-top:1px solid var(--line);padding:10px 0}
.f:first-of-type{border-top:0}
.f p{margin:3px 0}
.sev{display:inline-block;font-size:11px;font-weight:700;text-transform:uppercase;padding:1px 7px;border-radius:3px;color:#fff;background:var(--crit);margin-right:6px}
.sev.high{background:#c2410c}.sev.medium{background:var(--gap)}.sev.low{background:var(--na)}
.res{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--sky2);padding:1px 6px;border-radius:4px}
.table-wrap{overflow-x:auto;background:var(--paper);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}
.s-Pass{color:var(--ok);font-weight:600}.s-Fail{color:var(--crit);font-weight:600}.s-Not-assessed,.s-Not-applicable{color:var(--na)}
.disclaimer{margin-top:36px;color:var(--muted);font-size:13px}
@media print{header{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
"""


def to_html(r: Result) -> str:
    e = escape
    crit = sum(1 for f in r.findings if f.severity == "critical")
    score = "n/a" if r.readiness is None else f"{r.readiness:.0f}"
    cards = "".join(
        f'<div class="card c-{c.status.replace(" ", "-")}"><h3>{e(c.category)}</h3><span class="pill">{e(c.status)}</span>'
        f'<p>{c.checks_failed} of {c.checks} checks failing'
        f'{f", {c.resources_failing} resource" + ("s" if c.resources_failing != 1 else "") + " affected" if c.resources_failing else ""}</p></div>'
        for c in r.categories)
    areas = []
    for cat, fs in r.by_category().items():
        items = "".join(
            f'<div class="f"><p><span class="sev {f.severity}">{e(f.severity)}</span><strong>{e(f.check_id)}</strong> '
            f'{e(f.title)}: <span class="res">{e(f.resource)}</span></p><p>{e(f.detail)} '
            f'<span style="color:var(--muted)">Controls: {e(", ".join(f.controls))}.</span></p>'
            f'<p><strong>Fix:</strong> {e(f.remediation)}</p></div>' for f in fs)
        areas.append(f'<section class="area"><h3>{e(cat)}</h3>{items}</section>')
    if not areas:
        areas.append("<p>No findings.</p>")
    rows = "".join(
        f'<tr><td>{e(s.check_id)}</td><td>{e(s.category)}</td><td>{e(s.title)}</td><td>{e(", ".join(s.controls))}</td>'
        f'<td>{e(s.severity.title())}</td><td class="s-{STATUS_TEXT[s.status].replace(" ", "-")}">{STATUS_TEXT[s.status]}</td>'
        f'<td>{s.failed} of {s.in_scope}</td></tr>' for s in r.checks)
    inventory = ", ".join(f"{n} {TYPE_LABEL.get(t, t).lower()}{'s' if n != 1 else ''}" for t, n in r.resource_counts.items())
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>FedRAMP readiness pre-check: {e(r.organization)}</title><style>{_CSS}</style></head>
<body><header><div class="inner">
<h1>FedRAMP readiness pre-check: {e(r.organization)}</h1>
<p>{e(r.provider.upper())} configuration against the NIST SP 800-53 {e(r.baseline)} baseline. Generated {e(r.generated_at)} by cloud_check {e(r.tool_version)}.</p>
<div class="score"><div><div class="big">{score}<small> / 100</small></div><div class="lbl">Readiness: {e(r.readiness_label)}</div></div>
<div><div class="big">{crit}</div><div class="lbl">Critical findings</div></div>
<div><div class="big">{len(r.findings)}</div><div class="lbl">Total findings</div></div>
<div><div class="big">{r.resources}</div><div class="lbl">Resources checked</div></div></div>
</div></header>
<main>
<h2>Service areas</h2><div class="cards">{cards}</div>
<h2>Findings by service area</h2>{''.join(areas)}
<h2>All checks</h2><div class="table-wrap"><table><thead><tr><th>Check</th><th>Area</th><th>Title</th><th>Controls</th><th>Severity</th><th>Result</th><th>Failing</th></tr></thead><tbody>{rows}</tbody></table></div>
<p class="disclaimer">Inventory: {e(inventory)}. {e(DISCLAIMER)}</p>
</main></body></html>
"""


WRITERS = {"json": to_json, "csv": to_csv, "md": to_markdown, "html": to_html}
