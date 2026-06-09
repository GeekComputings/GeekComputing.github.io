"""Rule definition, validation, and evaluation.

A rule's ``check`` expresses the *failing* condition: when the condition is
true, the control is considered FAIL. This keeps rule authoring intuitive —
you describe the bad state you are looking for.

Fact paths use dot notation (``password_policy.min_length``) resolved against
the facts dict a collector produced. ``list:`` prefixed paths are treated as
collections so operators like ``count_gt`` can reason about how many items
tripped the check, and the offending items become the finding's evidence.
"""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass, field
from typing import Any, Callable

import yaml

from ..core.finding import FrameworkRefs, Severity

_MISSING = object()


def _resolve(path: str, facts: dict[str, Any]) -> Any:
    """Resolve a dotted ``path`` against ``facts``; return ``_MISSING`` if absent."""
    node: Any = facts
    for part in path.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return _MISSING
    return node


# Each operator answers: "given the fact value and the rule's threshold,
# is the control FAILING?" Operators returning True mean a problem exists.
Operator = Callable[[Any, Any], bool]

_OPERATORS: dict[str, Operator] = {
    "eq": lambda v, t: v == t,
    "ne": lambda v, t: v != t,
    "gt": lambda v, t: v is not _MISSING and v > t,
    "gte": lambda v, t: v is not _MISSING and v >= t,
    "lt": lambda v, t: v is not _MISSING and v < t,
    "lte": lambda v, t: v is not _MISSING and v <= t,
    "contains": lambda v, t: bool(v) and t in v,
    "not_contains": lambda v, t: not v or t not in v,
    "is_true": lambda v, t: v is True,
    "is_false": lambda v, t: v is False,
    "exists": lambda v, t: v is not _MISSING,
    "not_exists": lambda v, t: v is _MISSING,
    # collection operators: fact value must be a list
    "count_gt": lambda v, t: isinstance(v, list) and len(v) > t,
    "count_gte": lambda v, t: isinstance(v, list) and len(v) >= t,
    "non_empty": lambda v, t: isinstance(v, list) and len(v) > 0,
}


@dataclass
class RuleCheck:
    fact: str
    operator: str
    value: Any = None

    def validate(self) -> None:
        if self.operator not in _OPERATORS:
            raise ValueError(
                f"unknown operator {self.operator!r}; "
                f"valid: {', '.join(sorted(_OPERATORS))}"
            )

    def evaluate(self, facts: dict[str, Any]) -> tuple[bool, Any]:
        """Return ``(failed, evidence)``.

        ``evidence`` is the resolved fact value (or, for list checks, the
        offending items) so the report can show *why* the control failed.
        """
        resolved = _resolve(self.fact, facts)
        failed = _OPERATORS[self.operator](resolved, self.value)
        evidence = None if resolved is _MISSING else resolved
        return failed, evidence


@dataclass
class Rule:
    id: str
    title: str
    severity: Severity
    check: RuleCheck
    description: str = ""
    recommendation: str = ""
    category: str = ""
    references: FrameworkRefs = field(default_factory=FrameworkRefs)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Rule":
        try:
            check_raw = data["check"]
            check = RuleCheck(
                fact=check_raw["fact"],
                operator=check_raw["operator"],
                value=check_raw.get("value"),
            )
            refs_raw = data.get("references", {}) or {}
            rule = cls(
                id=data["id"],
                title=data["title"],
                severity=Severity.from_str(data["severity"]),
                check=check,
                description=data.get("description", ""),
                recommendation=data.get("recommendation", ""),
                category=data.get("category", ""),
                references=FrameworkRefs(
                    attack=list(refs_raw.get("attack", []) or []),
                    cis=list(refs_raw.get("cis", []) or []),
                    stig=list(refs_raw.get("stig", []) or []),
                ),
            )
        except KeyError as exc:
            raise ValueError(f"rule is missing required field: {exc}") from exc
        rule.check.validate()
        return rule


def load_rules_from_dir(directory: str) -> list[Rule]:
    """Load and validate every ``*.yaml`` rule under ``directory`` (recursively).

    Raises on the first malformed rule so a broken ruleset fails loudly rather
    than silently skipping checks.
    """
    paths = sorted(glob.glob(os.path.join(directory, "**", "*.yaml"), recursive=True))
    rules: list[Rule] = []
    seen: dict[str, str] = {}
    for path in paths:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not data:
            continue
        rule = Rule.from_dict(data)
        if rule.id in seen:
            raise ValueError(
                f"duplicate rule id {rule.id!r} in {path} (first seen in {seen[rule.id]})"
            )
        seen[rule.id] = path
        rules.append(rule)
    return rules
