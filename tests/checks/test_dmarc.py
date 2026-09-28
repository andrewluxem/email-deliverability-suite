import pytest

from deliv.checks.dmarc import check_dmarc
from deliv.lib.scoring import Status
from tests.fakes import FakeDNS


def run(record):
    zone = FakeDNS({("_dmarc.example.com", "TXT"): [record] if isinstance(record, str) else record})
    findings, tags = check_dmarc(zone.client(), "example.com")
    return {f.check: f for f in findings}, tags


def test_missing_dmarc_is_critical():
    checks, tags = run([])
    assert checks["DMARC record"].status is Status.FAIL
    assert checks["DMARC record"].critical
    assert tags is None


def test_multiple_records_fail():
    checks, _ = run(["v=DMARC1; p=none", "v=DMARC1; p=reject"])
    assert checks["DMARC record"].status is Status.FAIL


def test_missing_policy_fails():
    checks, _ = run("v=DMARC1; rua=mailto:d@example.com")
    assert checks["DMARC record"].status is Status.FAIL


@pytest.mark.parametrize(
    ("policy", "status"),
    [("none", Status.WARN), ("quarantine", Status.PASS), ("reject", Status.PASS)],
)
def test_policy_strength(policy, status):
    checks, tags = run(f"v=DMARC1; p={policy}; rua=mailto:d@example.com")
    assert checks["DMARC policy"].status is status
    assert tags["p"] == policy


@pytest.mark.parametrize(
    ("pct", "status"),
    [("100", Status.PASS), ("25", Status.WARN), ("abc", Status.WARN), ("150", Status.WARN)],
)
def test_pct(pct, status):
    checks, _ = run(f"v=DMARC1; p=quarantine; pct={pct}")
    assert checks["DMARC pct"].status is status


def test_pct_is_irrelevant_under_p_none():
    checks, _ = run("v=DMARC1; p=none; pct=10")
    assert checks["DMARC pct"].status is Status.PASS


def test_reporting_addresses():
    checks, _ = run("v=DMARC1; p=reject")
    assert checks["DMARC reporting"].status is Status.WARN
    checks, _ = run("v=DMARC1; p=reject; rua=mailto:a@example.com; ruf=mailto:f@example.com")
    assert checks["DMARC reporting"].status is Status.PASS
    assert "f@example.com" in checks["DMARC reporting"].message


@pytest.mark.parametrize(
    ("record", "status"),
    [
        ("v=DMARC1; p=reject; sp=none", Status.WARN),
        ("v=DMARC1; p=reject; sp=quarantine", Status.PASS),
        ("v=DMARC1; p=reject; sp=bogus", Status.WARN),
        ("v=DMARC1; p=reject", Status.PASS),
    ],
)
def test_subdomain_policy(record, status):
    checks, _ = run(record)
    assert checks["DMARC subdomains"].status is status


def test_alignment_is_informational():
    checks, _ = run("v=DMARC1; p=reject; adkim=s; aspf=r")
    alignment = checks["DMARC alignment"]
    assert alignment.status is Status.INFO
    assert alignment.details == {"adkim": "strict", "aspf": "relaxed"}
    assert alignment.remediation
