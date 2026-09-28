import pytest

from deliv.lib.scoring import (
    CRITICAL_CAP,
    Finding,
    Status,
    count_by_status,
    grade,
    score_findings,
    score_from_penalty,
    worst_status,
)


def f(status, weight=1.0, critical=False):
    return Finding("check", status, "message", weight=weight, critical=critical)


@pytest.mark.parametrize(
    ("score", "letter"),
    [
        (100, "A"),
        (90, "A"),
        (89, "B"),
        (80, "B"),
        (79, "C"),
        (70, "C"),
        (60, "D"),
        (59, "F"),
        (0, "F"),
    ],
)
def test_grade_thresholds(score, letter):
    assert grade(score) == letter


def test_all_pass_scores_100():
    assert score_findings([f(Status.PASS), f(Status.PASS)]) == 100


def test_warn_earns_half_credit_weighted():
    assert score_findings([f(Status.PASS, 3), f(Status.WARN, 1)]) == round(100 * 3.5 / 4)


def test_info_is_not_scored():
    assert score_findings([f(Status.PASS), f(Status.INFO)]) == 100
    assert score_findings([f(Status.INFO)]) == 100


def test_zero_weight_is_ignored():
    assert score_findings([f(Status.PASS), f(Status.FAIL, weight=0)]) == 100


def test_critical_failure_caps_score():
    findings = [f(Status.PASS, 10)] * 10 + [f(Status.FAIL, 0.1, critical=True)]
    assert score_findings(findings) == CRITICAL_CAP
    assert grade(score_findings(findings)) == "F"


def test_critical_pass_does_not_cap():
    assert score_findings([f(Status.PASS, critical=True)]) == 100


def test_score_from_penalty_clamps():
    assert score_from_penalty(0) == 100
    assert score_from_penalty(35.4) == 65
    assert score_from_penalty(250) == 0


def test_worst_status_and_counts():
    findings = [f(Status.PASS), f(Status.WARN), f(Status.INFO)]
    assert worst_status(findings) is Status.WARN
    assert worst_status([]) is Status.PASS
    assert worst_status([*findings, f(Status.FAIL)]) is Status.FAIL
    assert count_by_status(findings) == {"pass": 1, "warn": 1, "fail": 0, "info": 1}


def test_finding_to_dict_serializes_status():
    data = Finding("SPF", Status.WARN, "msg", "fix", "SPF", details={"a": 1}).to_dict()
    assert data["status"] == "warn"
    assert data["remediation"] == "fix"
    assert data["details"] == {"a": 1}
