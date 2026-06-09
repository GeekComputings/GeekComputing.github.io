"""The normalized finding model.

Every rule evaluation produces a :class:`Finding`. Collectors gather facts
and rules judge them, but the finding is the single shape the rest of the
system — scoring, reporting, future exports — speaks in.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.Enum):
    """Severity ordered from informational to critical.

    The numeric value doubles as the weight used by scoring.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:  # pragma: no cover - defensive
            raise ValueError(f"unknown severity: {value!r}") from exc

    def __str__(self) -> str:
        return self.name.capitalize()


class Status(enum.Enum):
    """Outcome of evaluating a rule against collected facts."""

    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"  # the rule could not be evaluated (missing facts, etc.)

    def __str__(self) -> str:
        return self.value


@dataclass
class FrameworkRefs:
    """Compliance/threat framework references attached to a finding.

    Keeping all three lenses on one object lets the report pivot between a
    compliance checklist and an adversary-technique view from one scan.
    """

    attack: list[str] = field(default_factory=list)  # MITRE ATT&CK technique IDs
    cis: list[str] = field(default_factory=list)  # CIS Benchmark control IDs
    stig: list[str] = field(default_factory=list)  # DISA STIG rule IDs

    def is_empty(self) -> bool:
        return not (self.attack or self.cis or self.stig)


@dataclass
class Finding:
    """The result of evaluating one rule against one target."""

    rule_id: str
    title: str
    target: str
    status: Status
    severity: Severity
    description: str = ""
    recommendation: str = ""
    evidence: Any = None
    references: FrameworkRefs = field(default_factory=FrameworkRefs)
    category: str = ""

    @property
    def passed(self) -> bool:
        return self.status is Status.PASS

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "target": self.target,
            "status": str(self.status),
            "severity": str(self.severity),
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "category": self.category,
            "references": {
                "attack": self.references.attack,
                "cis": self.references.cis,
                "stig": self.references.stig,
            },
        }
