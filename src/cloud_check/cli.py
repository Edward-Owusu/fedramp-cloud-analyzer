"""Command-line interface.

Examples:
    cloud-check samples/lakeside_route_software_aws.json
    cloud-check inventory.json --baseline low --format html csv --out reports --fail-on critical
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .checks import DataError, load_inventory
from .engine import BASELINES, assess, load_policy
from .reporting import WRITERS


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cloud-check",
                                description="FedRAMP-aligned readiness pre-check of a cloud configuration inventory.")
    p.add_argument("inventory", help="Path to the cloud inventory JSON file")
    p.add_argument("--baseline", choices=BASELINES, default="moderate", help="NIST SP 800-53 baseline (default: moderate)")
    p.add_argument("--format", nargs="+", choices=sorted(WRITERS), default=["html", "csv"])
    p.add_argument("--out", default="reports", help="Output directory (default: reports)")
    p.add_argument("--policy", help="JSON file overriding organization-defined parameters")
    p.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                   help="Exit with code 2 if any finding at or above this severity exists")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        inv = load_inventory(args.inventory)
        policy = load_policy(args.policy)
    except (OSError, DataError, ValueError) as exc:
        print(f"Could not read input: {exc}", file=sys.stderr)
        return 1
    r = assess(inv, args.baseline, policy)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stem = Path(args.inventory).stem + f"_{r.baseline}"
    for fmt in args.format:
        path = out / f"{stem}.{fmt}"
        path.write_text(WRITERS[fmt](r), encoding="utf-8")
        print(f"Wrote {path}")
    score = "n/a" if r.readiness is None else f"{r.readiness:.0f}/100"
    print(f"\n{r.organization} | {r.provider} | {r.baseline.title()} baseline | {r.resources} resources")
    print(f"Readiness: {score} ({r.readiness_label}) | Findings: {len(r.findings)}")
    for c in r.categories:
        print(f"  {c.category:<24} {c.status}")
    if args.fail_on:
        order = ["critical", "high", "medium", "low"]
        if any(order.index(f.severity) <= order.index(args.fail_on) for f in r.findings):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
