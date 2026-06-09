"""End-to-end: facts -> engine -> findings -> score -> report."""

from secaria.core.engine import Engine
from secaria.core.finding import Status
from secaria.core.scoring import score_findings
from secaria.reporting.report import render_html, render_text
from secaria.rules.schema import load_rules_from_dir


def _engine(rules_dir):
    return Engine(load_rules_from_dir(rules_dir))


def test_clean_domain_passes_everything(rules_dir, clean_facts):
    result = _engine(rules_dir).evaluate("secure", clean_facts)
    assert all(f.status is Status.PASS for f in result.findings)
    score = score_findings(result.findings)
    assert score.grade == "A"
    assert score.failed == 0


def test_weak_domain_produces_failures(rules_dir, weak_facts):
    result = _engine(rules_dir).evaluate("weak", weak_facts)
    failed = [f for f in result.findings if f.status is Status.FAIL]
    assert len(failed) >= 8
    score = score_findings(result.findings)
    assert score.grade in {"D", "F"}
    # the critical reversible-encryption finding must be present
    assert any(f.rule_id == "AD-REVERSIBLE-ENC" and f.status is Status.FAIL for f in result.findings)


def test_failing_finding_carries_evidence(rules_dir, weak_facts):
    result = _engine(rules_dir).evaluate("weak", weak_facts)
    krbtgt = next(f for f in result.findings if f.rule_id == "AD-KRBTGT-AGE")
    assert krbtgt.status is Status.FAIL
    assert krbtgt.evidence == 1200


def test_text_and_html_render(rules_dir, weak_facts):
    result = _engine(rules_dir).evaluate("weak", weak_facts)
    score = score_findings(result.findings)
    text = render_text(result, score)
    assert "Grade:" in text
    assert "AD-REVERSIBLE-ENC" in text
    html = render_html(result, score)
    assert "<html" in html.lower()
    assert "weak" in html
    assert "Reversible" in html


def test_scoring_weights_critical_highest(rules_dir):
    from secaria.core.scoring import SEVERITY_WEIGHT
    from secaria.core.finding import Severity

    assert SEVERITY_WEIGHT[Severity.CRITICAL] > SEVERITY_WEIGHT[Severity.HIGH]
    assert SEVERITY_WEIGHT[Severity.HIGH] > SEVERITY_WEIGHT[Severity.MEDIUM]
