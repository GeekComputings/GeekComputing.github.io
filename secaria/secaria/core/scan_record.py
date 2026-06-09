"""The persistent scan artifact: metadata + evidence + findings + score.

A :class:`ScanRecord` is what Secaria writes to JSON. It captures not just the
findings but *enough context to reproduce and compare them*: when the scan ran,
which tool and ruleset version produced it, how collection happened, and the
raw facts (evidence) the verdicts were derived from.

This is the foundation the rest of the roadmap stands on:

- **Re-evaluation** — load the saved facts and run a newer ruleset over them.
- **Diffing** — compare two records to see what changed between scans.
- **Auditing** — an assessor can verify each finding against the stored facts.
"""

from __future__ import annotations

import datetime
import json
from dataclasses import asdict, dataclass, field
from typing import Any

from .. import __version__
from .engine import AssessmentResult
from .finding import Finding
from .scoring import Score, score_findings

SCHEMA_VERSION = 1


def _utc_now_iso() -> str:
    return datetime.datetime.now(tz=datetime.timezone.utc).isoformat(timespec="seconds")


@dataclass
class ScanMetadata:
    """Provenance for a scan — the answers to who/what/when/how."""

    target: str
    kind: str = "ad"
    collection: str = "offline"  # "live" or "offline"
    generated_at: str = field(default_factory=_utc_now_iso)
    secaria_version: str = __version__
    schema_version: int = SCHEMA_VERSION
    ruleset_fingerprint: str = ""
    ruleset_count: int = 0
    stale_days: int = 90
    operator: str = ""  # who/what ran the scan (free-form, optional)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanMetadata":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class ScanRecord:
    metadata: ScanMetadata
    facts: dict[str, Any]
    findings: list[Finding]
    score: Score

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "score": self.score.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "facts": self.facts,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.to_json())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanRecord":
        findings = [Finding.from_dict(f) for f in data.get("findings", [])]
        score_data = data.get("score")
        # Recompute the score from findings if the stored block is absent, so
        # records hand-edited or produced by older versions still load.
        score = _score_from_dict(score_data) if score_data else score_findings(findings)
        return cls(
            metadata=ScanMetadata.from_dict(data.get("metadata", {})),
            facts=data.get("facts", {}),
            findings=findings,
            score=score,
        )

    @classmethod
    def load(cls, path: str) -> "ScanRecord":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))


def _score_from_dict(data: dict[str, Any]) -> Score:
    return Score(
        grade=data["grade"],
        risk_points=data["risk_points"],
        evaluated=data["evaluated"],
        passed=data["passed"],
        failed=data["failed"],
        errored=data["errored"],
        by_severity=data.get("by_severity", {}),
    )


def build_record(
    result: AssessmentResult,
    *,
    ruleset_fingerprint: str = "",
    ruleset_count: int = 0,
    collection: str = "offline",
    kind: str = "ad",
    stale_days: int = 90,
    operator: str = "",
    score: Score | None = None,
) -> ScanRecord:
    """Assemble a :class:`ScanRecord` from an assessment result and its context."""
    return ScanRecord(
        metadata=ScanMetadata(
            target=result.target,
            kind=kind,
            collection=collection,
            ruleset_fingerprint=ruleset_fingerprint,
            ruleset_count=ruleset_count,
            stale_days=stale_days,
            operator=operator,
        ),
        facts=result.facts,
        findings=result.findings,
        score=score or score_findings(result.findings),
    )
