"""Scan diffing: regressions, fixes, persistence, and dropped checks."""

import copy

from secaria.core.diffing import diff_records, render_diff_text
from secaria.core.engine import Engine
from secaria.core.scan_record import build_record
from secaria.rules.schema import load_rules_from_dir, ruleset_fingerprint


def _record(rules_dir, facts, target="corp"):
    engine = Engine(load_rules_from_dir(rules_dir))
    result = engine.evaluate(target, facts)
    return build_record(
        result,
        ruleset_fingerprint=ruleset_fingerprint(engine.rules),
        ruleset_count=len(engine.rules),
    )


def test_fixing_an_issue_shows_as_fixed(rules_dir, weak_facts, clean_facts):
    old = _record(rules_dir, weak_facts)
    new = _record(rules_dir, clean_facts)
    diff = diff_records(old, new)

    assert diff.fixed, "remediated controls should appear as fixed"
    assert not diff.regressed
    assert not diff.still_failing
    assert any(f.rule_id == "AD-REVERSIBLE-ENC" for f in diff.fixed)
    assert diff.rulesets_match


def test_regression_is_detected(rules_dir, weak_facts, clean_facts):
    old = _record(rules_dir, clean_facts)
    new = _record(rules_dir, weak_facts)
    diff = diff_records(old, new)

    assert diff.regressed
    assert not diff.fixed
    assert any(f.rule_id == "AD-REVERSIBLE-ENC" for f in diff.regressed)
    # regressed findings carry evidence from the new scan
    krbtgt = next(f for f in diff.regressed if f.rule_id == "AD-KRBTGT-AGE")
    assert krbtgt.evidence == weak_facts["krbtgt"]["password_age_days"]


def test_unchanged_failures_are_still_failing(rules_dir, weak_facts):
    old = _record(rules_dir, weak_facts)
    new = _record(rules_dir, weak_facts)
    diff = diff_records(old, new)

    assert not diff.regressed
    assert not diff.fixed
    assert diff.still_failing
    assert not diff.has_changes


def test_partial_fix(rules_dir, weak_facts):
    """Fix one thing, leave the rest: one fixed, the others still failing."""
    improved = copy.deepcopy(weak_facts)
    improved["password_policy"]["reversible_encryption"] = False  # fix the critical

    old = _record(rules_dir, weak_facts)
    new = _record(rules_dir, improved)
    diff = diff_records(old, new)

    assert [f.rule_id for f in diff.fixed] == ["AD-REVERSIBLE-ENC"]
    assert diff.still_failing
    assert not diff.regressed


def test_dropped_check_is_not_counted_as_fixed(rules_dir, weak_facts):
    """A finding that simply stops being evaluated must not read as fixed."""
    old = _record(rules_dir, weak_facts)
    new = _record(rules_dir, weak_facts)
    # Simulate the rule no longer producing a verdict in the new scan.
    new.findings = [f for f in new.findings if f.rule_id != "AD-KRBTGT-AGE"]

    diff = diff_records(old, new)
    assert any(f.rule_id == "AD-KRBTGT-AGE" for f in diff.no_longer_evaluated)
    assert not any(f.rule_id == "AD-KRBTGT-AGE" for f in diff.fixed)


def test_mismatched_fingerprint_flagged(rules_dir, weak_facts):
    old = _record(rules_dir, weak_facts)
    new = _record(rules_dir, weak_facts)
    new.metadata.ruleset_fingerprint = "deadbeef0000"
    diff = diff_records(old, new)
    assert diff.rulesets_match is False
    assert "fingerprints differ" in render_diff_text(diff)


def test_diff_to_dict_and_text_render(rules_dir, weak_facts, clean_facts):
    diff = diff_records(_record(rules_dir, weak_facts), _record(rules_dir, clean_facts))
    d = diff.to_dict()
    assert set(d) >= {"old", "new", "regressed", "fixed", "still_failing", "no_longer_evaluated"}
    text = render_diff_text(diff)
    assert "Secaria diff" in text
    assert "Fixed" in text
