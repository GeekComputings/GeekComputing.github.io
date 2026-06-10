"""Compare two scan records: what got worse, what got fixed, what persists.

The diff is keyed on ``(rule_id, target)`` and classifies each failing control
across the two scans:

- **regressed** — failing now, was passing (or absent) before
- **fixed** — was failing before, passing now
- **still_failing** — failing in both scans
- **no_longer_evaluated** — was failing before, but the rule produced no
  verdict this time (rule removed, or the fact disappeared / errored). These
  are surfaced separately because "we stopped checking" must never silently
  read as "we fixed it".

The ruleset fingerprint in each record's metadata tells the consumer whether
finding-level changes came from the environment or from edited rules; the diff
carries that signal rather than guessing.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .finding import Finding, Status
from .scan_record import ScanRecord

_SEV_DESC = lambda f: (-f.severity.value, f.rule_id)  # noqa: E731


def _key(f: Finding) -> tuple[str, str]:
    return (f.rule_id, f.target)


@dataclass
class ScanDiff:
    old_record: ScanRecord
    new_record: ScanRecord
    regressed: list[Finding] = field(default_factory=list)  # from the new scan
    fixed: list[Finding] = field(default_factory=list)  # from the old scan
    still_failing: list[Finding] = field(default_factory=list)  # from the new scan
    no_longer_evaluated: list[Finding] = field(default_factory=list)  # from the old scan

    @property
    def rulesets_match(self) -> bool:
        old_fp = self.old_record.metadata.ruleset_fingerprint
        new_fp = self.new_record.metadata.ruleset_fingerprint
        return bool(old_fp) and old_fp == new_fp

    @property
    def has_changes(self) -> bool:
        return bool(self.regressed or self.fixed or self.no_longer_evaluated)

    def to_dict(self) -> dict:
        return {
            "old": {
                "target": self.old_record.metadata.target,
                "generated_at": self.old_record.metadata.generated_at,
                "grade": self.old_record.score.grade,
                "risk_points": self.old_record.score.risk_points,
                "ruleset_fingerprint": self.old_record.metadata.ruleset_fingerprint,
            },
            "new": {
                "target": self.new_record.metadata.target,
                "generated_at": self.new_record.metadata.generated_at,
                "grade": self.new_record.score.grade,
                "risk_points": self.new_record.score.risk_points,
                "ruleset_fingerprint": self.new_record.metadata.ruleset_fingerprint,
            },
            "rulesets_match": self.rulesets_match,
            "regressed": [f.to_dict() for f in self.regressed],
            "fixed": [f.to_dict() for f in self.fixed],
            "still_failing": [f.to_dict() for f in self.still_failing],
            "no_longer_evaluated": [f.to_dict() for f in self.no_longer_evaluated],
        }


def diff_records(old: ScanRecord, new: ScanRecord) -> ScanDiff:
    old_by_key = {_key(f): f for f in old.findings}
    new_by_key = {_key(f): f for f in new.findings}

    diff = ScanDiff(old_record=old, new_record=new)

    for key, nf in new_by_key.items():
        if nf.status is not Status.FAIL:
            continue
        of = old_by_key.get(key)
        if of is not None and of.status is Status.FAIL:
            diff.still_failing.append(nf)
        else:
            diff.regressed.append(nf)

    for key, of in old_by_key.items():
        if of.status is not Status.FAIL:
            continue
        nf = new_by_key.get(key)
        if nf is None or nf.status is Status.ERROR:
            diff.no_longer_evaluated.append(of)
        elif nf.status is Status.PASS:
            diff.fixed.append(of)

    for bucket in (diff.regressed, diff.fixed, diff.still_failing, diff.no_longer_evaluated):
        bucket.sort(key=_SEV_DESC)
    return diff


def render_diff_text(diff: ScanDiff) -> str:
    old_m, new_m = diff.old_record.metadata, diff.new_record.metadata
    old_s, new_s = diff.old_record.score, diff.new_record.score
    lines = [
        f"Secaria diff — {new_m.target}",
        f"  old: {old_m.generated_at}  grade {old_s.grade}  risk {old_s.risk_points}",
        f"  new: {new_m.generated_at}  grade {new_s.grade}  risk {new_s.risk_points}",
    ]
    if not diff.rulesets_match:
        lines.append(
            "  note: ruleset fingerprints differ — some changes below may come "
            "from edited rules, not the environment."
        )
    lines.append("")

    def section(label: str, findings: list[Finding], mark: str) -> None:
        lines.append(f"{label} ({len(findings)}):")
        for f in findings:
            lines.append(f"  {mark} [{str(f.severity).upper():8}] {f.rule_id}  {f.title}")
            if mark == "+" and f.evidence is not None:
                lines.append(f"              evidence: {f.evidence}")
        if not findings:
            lines.append("  (none)")
        lines.append("")

    section("Regressed — failing now, was not before", diff.regressed, "+")
    section("Fixed — was failing, now passes", diff.fixed, "-")
    section("Still failing", diff.still_failing, "=")
    if diff.no_longer_evaluated:
        section(
            "No longer evaluated — was failing, no verdict now (NOT fixed)",
            diff.no_longer_evaluated,
            "?",
        )
    return "\n".join(lines).rstrip()
