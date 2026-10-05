"""Run the readiness pre-check over a cloud inventory."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .checks import CHECKS, FAIL, NOT_APPLICABLE, NOT_ASSESSED, PASS

DATA = Path(__file__).parent / "data"
BASELINES = ("low", "moderate", "high")
WEIGHTS = {"critical": 10, "high": 6, "medium": 3, "low": 1}
ORDER = list(WEIGHTS)
CATEGORIES = ["Identity", "Logging and monitoring", "Network", "Storage", "Databases", "Compute", "Encryption keys"]
READINESS_BANDS = [(90, "Strong"), (75, "Moderate gaps"), (50, "Significant gaps"), (0, "Not ready")]


def _load(name: str) -> dict:
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def load_policy(path: str | Path | None = None) -> dict:
    policy = _load("policy.json")
    if path:
        policy.update(json.loads(Path(path).read_text(encoding="utf-8")))
    return policy


@dataclass
class Finding:
    check_id: str
    category: str
    title: str
    severity: str
    controls: list[str]
    resource: str
    resource_type: str
    detail: str
    remediation: str


@dataclass
class CheckStat:
    check_id: str
    category: str
    title: str
    severity: str
    controls: list[str]
    status: str
    in_scope: int
    failed: int
    not_assessed: int


@dataclass
class CategorySummary:
    category: str
    status: str
    checks: int
    checks_failed: int
    resources_failing: int
    worst_severity: str | None


@dataclass
class Result:
    organization: str
    provider: str
    baseline: str
    generated_at: str
    tool_version: str
    readiness: float | None
    readiness_label: str
    resources: int
    resource_counts: dict[str, int]
    checks: list[CheckStat] = field(default_factory=list)
    categories: list[CategorySummary] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def by_category(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for f in self.findings:
            out.setdefault(f.category, []).append(f)
        return out

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def readiness_label(score: float) -> str:
    for floor, label in READINESS_BANDS:
        if score >= floor:
            return label
    return "Not ready"


def assess(inventory: dict, baseline: str = "moderate", policy: dict | None = None,
           organization: str | None = None) -> Result:
    from . import __version__

    baseline = baseline.lower()
    if baseline not in BASELINES:
        raise ValueError(f"Baseline must be one of {BASELINES}, got '{baseline}'")
    policy = policy or load_policy()
    in_baseline = {c["id"] for c in _load("controls.json")["controls"] if baseline in c["baselines"]}
    account = inventory.get("account", {})
    resources = inventory.get("resources", [])

    findings: list[Finding] = []
    stats: list[CheckStat] = []
    for meta in _load("checks.json")["checks"]:
        controls = [c for c in meta["controls"] if c in in_baseline]
        if not controls:
            continue
        target, fn = CHECKS[meta["id"]]
        subjects = ([(account.get("name") or "Cloud account", "account", account)] if target == "account"
                    else [(r.get("name") or r["id"], r["type"], r) for r in resources if r["type"] == target])
        in_scope = failed = missing = 0
        for name, rtype, obj in subjects:
            out = fn(obj, policy)
            if out is None:
                continue
            in_scope += 1
            if out == NOT_ASSESSED:
                missing += 1
            elif out[0] == FAIL:
                failed += 1
                findings.append(Finding(meta["id"], meta["category"], meta["title"], meta["severity"], controls,
                                        name, rtype, out[1], meta["remediation"]))
        if in_scope == 0:
            status = NOT_APPLICABLE
        elif failed:
            status = FAIL
        elif in_scope == missing:
            status = NOT_ASSESSED
        else:
            status = PASS
        stats.append(CheckStat(meta["id"], meta["category"], meta["title"], meta["severity"], controls,
                               status, in_scope, failed, missing))

    total_w = fail_w = 0.0
    for s in stats:
        assessed = s.in_scope - s.not_assessed
        if assessed > 0:
            total_w += WEIGHTS[s.severity]
            fail_w += WEIGHTS[s.severity] * s.failed / assessed
    readiness = round(100 * (1 - fail_w / total_w), 1) if total_w else None

    cats = []
    for cat in CATEGORIES:
        cs = [s for s in stats if s.category == cat]
        if not cs:
            continue
        cf = [f for f in findings if f.category == cat]
        worst = min((f.severity for f in cf), key=ORDER.index) if cf else None
        if all(s.status in (NOT_APPLICABLE, NOT_ASSESSED) for s in cs):
            status = "No data"
        elif not cf:
            status = "Pass"
        elif worst == "critical":
            status = "Critical gaps"
        else:
            status = "Gaps"
        cats.append(CategorySummary(cat, status, len(cs), sum(1 for s in cs if s.status == FAIL),
                                    len({f.resource for f in cf}), worst))

    counts: dict[str, int] = {}
    for r in resources:
        counts[r["type"]] = counts.get(r["type"], 0) + 1
    findings.sort(key=lambda f: (ORDER.index(f.severity), CATEGORIES.index(f.category), f.check_id, f.resource))
    return Result(
        organization=organization or inventory.get("organization", "Unnamed organization"),
        provider=inventory.get("provider", "unspecified"),
        baseline=baseline,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        tool_version=__version__,
        readiness=readiness,
        readiness_label=readiness_label(readiness) if readiness is not None else "Not rated",
        resources=len(resources),
        resource_counts=counts,
        checks=stats,
        categories=cats,
        findings=findings,
    )
