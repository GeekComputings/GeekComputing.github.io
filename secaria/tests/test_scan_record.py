"""Scan-record serialization: the foundation for diffing and re-evaluation."""

import json

from secaria.core.engine import Engine
from secaria.core.scan_record import ScanRecord, build_record
from secaria.core.scoring import score_findings
from secaria.rules.schema import load_rules_from_dir, ruleset_fingerprint


def _record(rules_dir, facts, **kw):
    engine = Engine(load_rules_from_dir(rules_dir))
    result = engine.evaluate("corp", facts)
    return engine, build_record(
        result,
        ruleset_fingerprint=ruleset_fingerprint(engine.rules),
        ruleset_count=len(engine.rules),
        **kw,
    )


def test_record_roundtrips_through_json(rules_dir, weak_facts):
    _, record = _record(rules_dir, weak_facts, collection="offline", stale_days=90)
    restored = ScanRecord.from_dict(json.loads(record.to_json()))

    assert restored.metadata.target == "corp"
    assert restored.metadata.ruleset_count == record.metadata.ruleset_count
    assert restored.facts == weak_facts
    assert len(restored.findings) == len(record.findings)
    # the score survives the round trip
    assert restored.score.grade == record.score.grade
    assert restored.score.failed == record.score.failed


def test_record_captures_metadata(rules_dir, weak_facts):
    _, record = _record(rules_dir, weak_facts, collection="live", operator="ci-bot")
    d = record.to_dict()
    assert d["metadata"]["collection"] == "live"
    assert d["metadata"]["operator"] == "ci-bot"
    assert d["metadata"]["schema_version"] == 1
    assert d["metadata"]["secaria_version"]
    assert d["metadata"]["generated_at"].endswith("+00:00")
    # evidence is preserved for auditing
    assert d["facts"]["krbtgt"]["password_age_days"] == 1200


def test_record_save_and_load(tmp_path, rules_dir, weak_facts):
    _, record = _record(rules_dir, weak_facts)
    path = tmp_path / "scan.json"
    record.save(str(path))
    loaded = ScanRecord.load(str(path))
    assert loaded.metadata.target == "corp"
    assert loaded.score.failed == record.score.failed


def test_fingerprint_is_stable_and_logic_sensitive(rules_dir):
    rules = load_rules_from_dir(rules_dir)
    fp1 = ruleset_fingerprint(rules)
    fp2 = ruleset_fingerprint(list(reversed(rules)))  # order-independent
    assert fp1 == fp2
    # changing a threshold changes the fingerprint
    rules[0].check.value = (rules[0].check.value or 0) + 999
    assert ruleset_fingerprint(rules) != fp1


def test_reevaluating_saved_facts_matches_original(rules_dir, weak_facts):
    """A record's stored facts can be re-run and reproduce the verdicts."""
    engine = Engine(load_rules_from_dir(rules_dir))
    original = engine.evaluate("corp", weak_facts)
    record = build_record(original)

    rerun = engine.evaluate("corp", record.facts)
    assert score_findings(rerun.findings).grade == score_findings(original.findings).grade
