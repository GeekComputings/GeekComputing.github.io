"""Render an assessment into HTML (exec summary + technical detail) and text.

The HTML report leads with the posture grade and a severity breakdown for a
non-technical reader, then lists every failing finding with evidence and
remediation for the engineer who has to fix it. Passing controls are kept in
a collapsed section so the report doubles as an audit trail.
"""

from __future__ import annotations

import datetime
import html
import os
from typing import Iterable

from ..core.engine import AssessmentResult
from ..core.finding import Finding, Severity, Status
from ..core.scoring import Score, score_findings
from ..frameworks.references import attack_url, describe_attack

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _sorted_failures(findings: Iterable[Finding]) -> list[Finding]:
    fails = [f for f in findings if f.status is Status.FAIL]
    return sorted(fails, key=lambda f: (-f.severity.value, f.rule_id))


def render_text(result: AssessmentResult, score: Score | None = None) -> str:
    score = score or score_findings(result.findings)
    lines = [
        f"Secaria assessment — {result.target}",
        f"Grade: {score.grade}   Risk points: {score.risk_points}   "
        f"Pass rate: {score.pass_rate:.0f}%",
        f"Evaluated: {score.evaluated}  Failed: {score.failed}  "
        f"Passed: {score.passed}  Errored: {score.errored}",
        "",
        "Findings (failing, by severity):",
    ]
    for f in _sorted_failures(result.findings):
        lines.append(f"  [{str(f.severity).upper():8}] {f.rule_id}  {f.title}")
        if f.evidence is not None:
            lines.append(f"            evidence: {f.evidence}")
    if score.failed == 0:
        lines.append("  (none — all evaluated controls passed)")
    return "\n".join(lines)


def _finding_html(f: Finding) -> str:
    refs = []
    for t in f.references.attack:
        refs.append(f'<a href="{attack_url(t)}">{html.escape(describe_attack(t))}</a>')
    for c in f.references.cis:
        refs.append(f"CIS {html.escape(c)}")
    for s in f.references.stig:
        refs.append(f"STIG {html.escape(s)}")
    refs_html = " · ".join(refs) if refs else "—"
    evidence_html = (
        f"<pre class='evidence'>{html.escape(str(f.evidence))}</pre>"
        if f.evidence is not None
        else ""
    )
    sev = str(f.severity).lower()
    return f"""
    <div class="finding sev-{sev}">
      <div class="finding-head">
        <span class="badge sev-{sev}">{html.escape(str(f.severity))}</span>
        <span class="rule-id">{html.escape(f.rule_id)}</span>
        <span class="title">{html.escape(f.title)}</span>
      </div>
      <p class="desc">{html.escape(f.description)}</p>
      {evidence_html}
      <p class="rec"><strong>Remediation:</strong> {html.escape(f.recommendation)}</p>
      <p class="refs">{refs_html}</p>
    </div>"""


def render_html(result: AssessmentResult, score: Score | None = None) -> str:
    score = score or score_findings(result.findings)
    generated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    failures = _sorted_failures(result.findings)
    passes = [f for f in result.findings if f.status is Status.PASS]

    sev_cards = "".join(
        f'<div class="sev-card sev-{s.name.lower()}">'
        f'<div class="n">{score.by_severity.get(str(s), 0)}</div>'
        f'<div class="l">{str(s)}</div></div>'
        for s in _SEVERITY_ORDER
        if s is not Severity.INFO
    )
    failures_html = "".join(_finding_html(f) for f in failures) or (
        "<p>No failing controls — every evaluated check passed.</p>"
    )
    passes_html = "".join(
        f'<li><span class="rule-id">{html.escape(f.rule_id)}</span> {html.escape(f.title)}</li>'
        for f in passes
    )

    template_path = os.path.join(os.path.dirname(__file__), "templates", "report.html")
    with open(template_path, "r", encoding="utf-8") as fh:
        template = fh.read()

    return (
        template.replace("{{TARGET}}", html.escape(result.target))
        .replace("{{GENERATED}}", generated)
        .replace("{{GRADE}}", score.grade)
        .replace("{{GRADE_CLASS}}", f"grade-{score.grade.lower()}")
        .replace("{{RISK}}", str(score.risk_points))
        .replace("{{PASSRATE}}", f"{score.pass_rate:.0f}")
        .replace("{{EVALUATED}}", str(score.evaluated))
        .replace("{{FAILED}}", str(score.failed))
        .replace("{{PASSED}}", str(score.passed))
        .replace("{{SEV_CARDS}}", sev_cards)
        .replace("{{FAILURES}}", failures_html)
        .replace("{{PASSES}}", passes_html)
    )
