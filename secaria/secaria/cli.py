"""Secaria command-line interface.

Three commands:

  secaria scan   — assess a target (live LDAP, or --facts for offline)
  secaria rules  — list the loaded ruleset
  secaria report — render a saved facts file straight to an HTML report

Offline mode (``--facts FILE``) needs no domain controller, which makes the
whole pipeline demonstrable and testable from a captured facts file.
"""

from __future__ import annotations

import argparse
import os
import sys

from .core.engine import Engine, collect_facts, load_facts_file
from .core.scan_record import build_record
from .core.scoring import score_findings
from .core.target import Credential, Target
from .reporting.report import render_html, render_text
from .rules.schema import load_rules_from_dir, ruleset_fingerprint

DEFAULT_RULES_DIR = os.path.join(os.path.dirname(__file__), "rules", "ad")


def _load_engine(rules_dir: str) -> Engine:
    rules = load_rules_from_dir(rules_dir)
    if not rules:
        print(f"warning: no rules loaded from {rules_dir}", file=sys.stderr)
    return Engine(rules)


def _cmd_rules(args) -> int:
    engine = _load_engine(args.rules_dir)
    for r in engine.rules:
        refs = ", ".join(r.references.attack) or "—"
        print(f"{r.id:24} [{str(r.severity):8}] {r.title}  (ATT&CK: {refs})")
    print(f"\n{len(engine.rules)} rules loaded from {args.rules_dir}")
    return 0


def _load_facts_or_record(path: str) -> dict:
    """Load a ``--facts`` file that is either raw facts or a saved scan record.

    A scan record nests the captured facts under a ``facts`` key alongside
    ``metadata``; pulling them back out lets you re-evaluate an old scan against
    the current ruleset.
    """
    data = load_facts_file(path)
    if isinstance(data, dict) and "metadata" in data and "facts" in data:
        return data["facts"]
    return data


def _get_facts(args) -> tuple[str, dict, str]:
    """Return (target_name, facts, collection_mode)."""
    if args.facts:
        name = args.target or os.path.basename(args.facts)
        return name, _load_facts_or_record(args.facts), "offline"
    if not args.target:
        raise SystemExit("error: --target is required for live collection")
    cred = Credential.from_env()
    if cred is None:
        raise SystemExit(
            "error: live collection needs SECARIA_USERNAME / SECARIA_PASSWORD "
            "(and optionally SECARIA_DOMAIN) in the environment, or use --facts."
        )
    target = Target(
        host=args.target,
        kind=args.kind,
        authorized=args.i_have_authorization,
        credential=cred,
    )
    return args.target, collect_facts(target, stale_days=args.stale_days), "live"


def _cmd_scan(args) -> int:
    engine = _load_engine(args.rules_dir)
    target_name, facts, collection = _get_facts(args)
    result = engine.evaluate(target_name, facts)
    score = score_findings(result.findings)

    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(render_html(result, score))
        print(f"wrote HTML report to {args.html}")
    if args.json:
        record = build_record(
            result,
            ruleset_fingerprint=ruleset_fingerprint(engine.rules),
            ruleset_count=len(engine.rules),
            collection=collection,
            kind=args.kind,
            stale_days=args.stale_days,
            operator=args.operator or "",
        )
        record.save(args.json)
        print(f"wrote scan record to {args.json}")
    print(render_text(result, score))
    # Non-zero exit when high/critical findings exist, so CI can gate on it.
    high = score.by_severity.get("High", 0) + score.by_severity.get("Critical", 0)
    return 2 if high else 0


def _cmd_report(args) -> int:
    engine = _load_engine(args.rules_dir)
    facts = _load_facts_or_record(args.facts)
    name = args.target or os.path.basename(args.facts)
    result = engine.evaluate(name, facts)
    out = args.html or "secaria-report.html"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(render_html(result))
    print(f"wrote HTML report to {out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secaria", description="Agentless security posture assessment.")
    p.add_argument("--rules-dir", default=DEFAULT_RULES_DIR, help="directory of rule YAML files")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="assess a target")
    scan.add_argument("--target", help="hostname/IP of the domain controller")
    scan.add_argument("--kind", default="ad", help="target kind (only 'ad' in this slice)")
    scan.add_argument(
        "--facts",
        help="evaluate a saved facts JSON file or a prior scan record instead of live collection",
    )
    scan.add_argument("--html", help="also write an HTML report to this path")
    scan.add_argument("--json", help="write a machine-readable scan record (metadata + evidence + findings) to this path")
    scan.add_argument("--operator", help="who/what ran this scan, recorded in the scan metadata")
    scan.add_argument("--stale-days", type=int, default=90, help="inactivity threshold for stale accounts")
    scan.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="confirm you are authorized to assess this target (required for live collection)",
    )
    scan.set_defaults(func=_cmd_scan)

    rules = sub.add_parser("rules", help="list loaded rules")
    rules.set_defaults(func=_cmd_rules)

    report = sub.add_parser("report", help="render a saved facts file to HTML")
    report.add_argument("--facts", required=True, help="saved facts JSON file")
    report.add_argument("--target", help="name to label the report with")
    report.add_argument("--html", help="output HTML path (default secaria-report.html)")
    report.set_defaults(func=_cmd_report)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
