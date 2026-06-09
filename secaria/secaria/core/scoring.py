"""Turn a set of findings into a risk score and a posture grade.

The model is intentionally simple and explainable: each failing finding
contributes a weight derived from its severity, the weighted failures are
expressed as a percentage of the worst-case weight, and that maps to a
letter grade. Nothing here is a secret formula — a reader should be able to
follow exactly why a domain scored a C.
"""

from __future__ import annotations

from dataclasses import dataclass

from .finding import Finding, Severity, Status

# Weight contributed by a single failing finding of each severity.
SEVERITY_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 3,
    Severity.HIGH: 7,
    Severity.CRITICAL: 12,
}


@dataclass
class Score:
    grade: str
    risk_points: int
    evaluated: int
    passed: int
    failed: int
    errored: int
    by_severity: dict[str, int]  # count of FAILING findings per severity name

    @property
    def pass_rate(self) -> float:
        scored = self.passed + self.failed
        return (self.passed / scored * 100) if scored else 100.0

    def to_dict(self) -> dict:
        return {
            "grade": self.grade,
            "risk_points": self.risk_points,
            "pass_rate": round(self.pass_rate, 1),
            "evaluated": self.evaluated,
            "passed": self.passed,
            "failed": self.failed,
            "errored": self.errored,
            "by_severity": self.by_severity,
        }


def _grade(risk_points: int, max_points: int) -> str:
    if max_points == 0:
        return "A"
    ratio = risk_points / max_points
    if ratio == 0:
        return "A"
    if ratio < 0.10:
        return "B"
    if ratio < 0.25:
        return "C"
    if ratio < 0.50:
        return "D"
    return "F"


def score_findings(findings: list[Finding]) -> Score:
    """Aggregate findings into a :class:`Score`.

    ``max_points`` is the risk we would accrue if every evaluated control
    failed, which keeps the grade meaningful regardless of how many rules ran.
    """

    risk_points = 0
    max_points = 0
    passed = failed = errored = 0
    by_severity: dict[str, int] = {s.name.capitalize(): 0 for s in Severity}

    for f in findings:
        if f.status is Status.ERROR:
            errored += 1
            continue
        weight = SEVERITY_WEIGHT[f.severity]
        max_points += weight
        if f.status is Status.FAIL:
            failed += 1
            risk_points += weight
            by_severity[str(f.severity)] += 1
        else:
            passed += 1

    return Score(
        grade=_grade(risk_points, max_points),
        risk_points=risk_points,
        evaluated=passed + failed,
        passed=passed,
        failed=failed,
        errored=errored,
        by_severity=by_severity,
    )
