"""Data-defined rules: the extensible heart of Secaria.

A rule is a YAML document, not code. It names a fact to inspect, the
condition that constitutes a *failure*, the remediation advice, and the
framework references. New checks are added by dropping in a YAML file —
the engine never changes.
"""

from .schema import Rule, RuleCheck, load_rules_from_dir  # noqa: F401
