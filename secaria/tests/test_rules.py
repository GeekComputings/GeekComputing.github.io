"""Validate the shipped ruleset and the rule-evaluation operators."""

from secaria.core.finding import FrameworkRefs, Severity
from secaria.rules.schema import Rule, RuleCheck, load_rules_from_dir


def test_ruleset_loads_and_is_valid(rules_dir):
    rules = load_rules_from_dir(rules_dir)
    assert len(rules) >= 10
    # ids are unique (load_rules_from_dir would raise otherwise) and non-empty
    assert all(r.id for r in rules)
    # every rule carries at least one framework reference
    for r in rules:
        assert not r.references.is_empty(), f"{r.id} has no framework references"


def test_every_rule_has_recommendation(rules_dir):
    for r in load_rules_from_dir(rules_dir):
        assert r.recommendation.strip(), f"{r.id} is missing remediation guidance"


def test_operator_gt():
    check = RuleCheck(fact="krbtgt.password_age_days", operator="gt", value=180)
    failed, evidence = check.evaluate({"krbtgt": {"password_age_days": 940}})
    assert failed is True
    assert evidence == 940


def test_operator_gt_passing():
    check = RuleCheck(fact="krbtgt.password_age_days", operator="gt", value=180)
    failed, _ = check.evaluate({"krbtgt": {"password_age_days": 10}})
    assert failed is False


def test_operator_non_empty_list():
    check = RuleCheck(fact="unconstrained_delegation", operator="non_empty")
    failed, evidence = check.evaluate({"unconstrained_delegation": ["WEB01$"]})
    assert failed is True
    assert evidence == ["WEB01$"]


def test_operator_is_false():
    check = RuleCheck(fact="password_policy.complexity", operator="is_false")
    failed, _ = check.evaluate({"password_policy": {"complexity": False}})
    assert failed is True


def test_missing_fact_does_not_crash():
    check = RuleCheck(fact="password_policy.min_length", operator="lt", value=14)
    failed, evidence = check.evaluate({})  # fact absent
    assert failed is False
    assert evidence is None


def test_unknown_operator_rejected():
    import pytest

    with pytest.raises(ValueError):
        RuleCheck(fact="x", operator="nonsense").validate()


def test_rule_from_dict_roundtrip():
    rule = Rule.from_dict(
        {
            "id": "X-1",
            "title": "t",
            "severity": "high",
            "check": {"fact": "a.b", "operator": "eq", "value": 1},
            "recommendation": "fix it",
            "references": {"attack": ["T1110"]},
        }
    )
    assert rule.severity is Severity.HIGH
    assert isinstance(rule.references, FrameworkRefs)
    assert rule.references.attack == ["T1110"]
