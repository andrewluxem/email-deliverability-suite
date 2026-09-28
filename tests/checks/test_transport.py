import pytest

from deliv.checks.transport import check_mta_sts, check_tls_rpt, parse_mta_sts_policy
from deliv.lib.http import FetchError
from deliv.lib.scoring import Status
from tests.dns_fixtures import ENFORCE_POLICY, POLICY_URL, healthy_fetcher, healthy_zone
from tests.fakes import FakeDNS, FakeFetcher


def mta(zone, fetcher):
    return {f.check: f for f in check_mta_sts(zone.client(), "example.com", fetcher, 5)}


def test_parse_valid_policy():
    policy, errors = parse_mta_sts_policy(ENFORCE_POLICY)
    assert errors == []
    assert policy["mode"] == "enforce"
    assert policy["max_age"] == 604800
    assert policy["mx"] == ["*.example.com"]


@pytest.mark.parametrize(
    ("text", "error"),
    [
        ("version: STSv2\nmode: enforce\nmx: a.example.com\nmax_age: 1", "version"),
        ("version: STSv1\nmode: strict\nmx: a.example.com\nmax_age: 1", "mode"),
        ("version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: soon", "max_age"),
        ("version: STSv1\nmode: enforce\nmax_age: 1", "mx"),
        ("version STSv1", "malformed"),
    ],
)
def test_parse_invalid_policy(text, error):
    _, errors = parse_mta_sts_policy(text)
    assert any(error in e for e in errors)


def test_healthy_mta_sts_passes():
    checks = mta(healthy_zone(), healthy_fetcher())
    assert checks["MTA-STS record"].status is Status.PASS
    assert checks["MTA-STS policy"].status is Status.PASS


def test_missing_record_warns_and_skips_fetch():
    fetcher = FakeFetcher()
    checks = mta(FakeDNS(), fetcher)
    assert checks["MTA-STS record"].status is Status.WARN
    assert "MTA-STS policy" not in checks
    assert fetcher.calls == []


def test_record_without_id_warns():
    zone = healthy_zone().add("_mta-sts.example.com", "TXT", ["v=STSv1;"])
    assert mta(zone, healthy_fetcher())["MTA-STS record"].status is Status.WARN


def test_fetch_failure_warns_not_crashes():
    fetcher = FakeFetcher({POLICY_URL: FetchError("timed out")})
    finding = mta(healthy_zone(), fetcher)["MTA-STS policy"]
    assert finding.status is Status.WARN
    assert "timed out" in finding.message


def test_testing_mode_warns():
    fetcher = FakeFetcher({POLICY_URL: ENFORCE_POLICY.replace("enforce", "testing")})
    assert mta(healthy_zone(), fetcher)["MTA-STS policy"].status is Status.WARN


def test_invalid_policy_fails():
    fetcher = FakeFetcher({POLICY_URL: "version: STSv1\nmode: enforce\n"})
    assert mta(healthy_zone(), fetcher)["MTA-STS policy"].status is Status.FAIL


def test_enforce_policy_must_cover_every_mx():
    zone = healthy_zone().add("example.com", "MX", ["10 mx1.example.com", "20 inbound.example.net"])
    finding = mta(zone, healthy_fetcher())["MTA-STS policy"]
    assert finding.status is Status.FAIL
    assert finding.details["unmatched_mx"] == ["inbound.example.net"]


def test_wildcard_matches_one_label_only():
    zone = healthy_zone().add("example.com", "MX", ["10 a.b.example.com"])
    assert mta(zone, healthy_fetcher())["MTA-STS policy"].status is Status.FAIL


def test_tls_rpt():
    (finding,) = check_tls_rpt(healthy_zone().client(), "example.com")
    assert finding.status is Status.PASS
    (finding,) = check_tls_rpt(FakeDNS().client(), "example.com")
    assert finding.status is Status.WARN
    zone = FakeDNS({("_smtp._tls.example.com", "TXT"): ["v=TLSRPTv1;"]})
    (finding,) = check_tls_rpt(zone.client(), "example.com")
    assert finding.status is Status.WARN
