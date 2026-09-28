from deliv.checks.bimi import check_bimi
from deliv.lib.scoring import Status
from tests.fakes import FakeDNS

NAME = "default._bimi.example.com"


def run(records, policy="reject"):
    (finding,) = check_bimi(FakeDNS({(NAME, "TXT"): records}).client(), "example.com", policy)
    return finding


def test_missing_bimi_is_info_and_mentions_vmc():
    finding = run([])
    assert finding.status is Status.INFO
    assert "Verified Mark Certificate" in finding.remediation


def test_complete_bimi_passes():
    record = "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"
    assert run([record]).status is Status.PASS


def test_bimi_without_vmc_warns():
    finding = run(["v=BIMI1; l=https://example.com/logo.svg"])
    assert finding.status is Status.WARN
    assert "VMC" in finding.remediation


def test_bimi_requires_enforcing_dmarc():
    record = "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"
    assert run([record], policy="none").status is Status.WARN


def test_bimi_logo_must_be_https():
    assert run(["v=BIMI1; l=http://example.com/logo.svg; a="]).status is Status.WARN


def test_bimi_lookup_error_is_info():
    assert run("timeout").status is Status.INFO
