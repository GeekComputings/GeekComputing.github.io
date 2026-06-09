"""The assessment engine: scope → collect → evaluate → findings.

The engine is deliberately thin. It knows how to obtain facts (from a live
collector or a saved file) and how to run a ruleset over those facts. All
domain knowledge lives in collectors and rules.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional

from ..rules.schema import Rule
from .finding import Finding, Status
from .target import Target


@dataclass
class AssessmentResult:
    target: str
    facts: dict[str, Any]
    findings: list[Finding]


class Engine:
    def __init__(self, rules: list[Rule]):
        self.rules = rules

    def evaluate(self, target_name: str, facts: dict[str, Any]) -> AssessmentResult:
        """Run every rule against ``facts`` and return the findings."""
        findings: list[Finding] = []
        for rule in self.rules:
            findings.append(self._apply(rule, target_name, facts))
        return AssessmentResult(target=target_name, facts=facts, findings=findings)

    def _apply(self, rule: Rule, target_name: str, facts: dict[str, Any]) -> Finding:
        try:
            failed, evidence = rule.check.evaluate(facts)
        except Exception:  # a malformed fact shouldn't abort the whole scan
            return Finding(
                rule_id=rule.id,
                title=rule.title,
                target=target_name,
                status=Status.ERROR,
                severity=rule.severity,
                description=rule.description,
                recommendation=rule.recommendation,
                category=rule.category,
                references=rule.references,
            )
        return Finding(
            rule_id=rule.id,
            title=rule.title,
            target=target_name,
            status=Status.FAIL if failed else Status.PASS,
            severity=rule.severity,
            description=rule.description,
            recommendation=rule.recommendation,
            evidence=evidence if failed else None,
            category=rule.category,
            references=rule.references,
        )


def load_facts_file(path: str) -> dict[str, Any]:
    """Load a saved facts JSON file for offline evaluation."""
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def collect_facts(target: Target, stale_days: int = 90) -> dict[str, Any]:
    """Run the collector matching ``target.kind`` and return its facts."""
    if target.kind == "ad":
        from ..collectors.activedirectory import ActiveDirectoryCollector

        return ActiveDirectoryCollector(target, stale_days=stale_days).collect()
    raise NotImplementedError(
        f"no collector for target kind {target.kind!r} yet (only 'ad' in this slice)"
    )
