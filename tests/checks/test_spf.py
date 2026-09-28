import pytest

from deliv.checks.spf import check_spf, count_spf_lookups, parse_spf
from deliv.lib.scoring import Status
from tests.fakes import FakeDNS


def spf_findings(zone, domain="example.com"):
    findings, _ = check_spf(zone.client(), domain)
    return {f.check: f for f in findings}


def test_parse_spf_terms_and_qualifiers():
    terms, errors = parse_spf(
        "v=spf1 ip4:192.0.2.0/24 a/24 mx include:x.example.net ~all redirect=y"
    )
    assert errors == []
    assert [t.name for t in terms] == ["ip4", "a", "mx", "include", "all", "redirect"]
    assert terms[4].qualifier == "~"
    assert terms[5].kind == "modifier"


@pytest.mark.parametrize(
    ("record", "error"),
    [
        ("v=spf1 bogus:x -all", "unknown mechanism"),
        ("v=spf1 include: -all", "requires a value"),
        ("spf1 -all", "does not start with v=spf1"),
    ],
)
def test_parse_spf_errors(record, error):
    _, errors = parse_spf(record)
    assert any(error in e for e in errors)


def test_missing_spf_is_critical_fail():
    checks = spf_findings(FakeDNS())
    assert checks["SPF record"].status is Status.FAIL
    assert checks["SPF record"].critical


def test_multiple_spf_records_fail():
    zone = FakeDNS({("example.com", "TXT"): ["v=spf1 -all", "v=spf1 ~all"]})
    assert spf_findings(zone)["SPF record"].status is Status.FAIL


def test_plus_all_is_critical_fail():
    zone = FakeDNS({("example.com", "TXT"): ["v=spf1 +all"]})
    policy = spf_findings(zone)["SPF policy"]
    assert policy.status is Status.FAIL
    assert policy.critical


def test_bare_all_is_treated_as_plus_all():
    zone = FakeDNS({("example.com", "TXT"): ["v=spf1 ip4:192.0.2.1 all"]})
    assert spf_findings(zone)["SPF policy"].status is Status.FAIL


@pytest.mark.parametrize(
    ("record", "status"),
    [
        ("v=spf1 -all", Status.PASS),
        ("v=spf1 ~all", Status.PASS),
        ("v=spf1 ?all", Status.WARN),
        ("v=spf1 ip4:192.0.2.1", Status.WARN),
        ("v=spf1 redirect=_spf.example.com", Status.PASS),
    ],
)
def test_all_qualifiers(record, status):
    zone = FakeDNS({("example.com", "TXT"): [record], ("_spf.example.com", "TXT"): ["v=spf1 -all"]})
    assert spf_findings(zone)["SPF policy"].status is status


def test_ptr_is_a_warning():
    zone = FakeDNS({("example.com", "TXT"): ["v=spf1 ptr -all"]})
    assert spf_findings(zone)["SPF record"].status is Status.WARN


def _chain(count):
    """Build a zone whose SPF needs exactly `count` lookups via nested includes."""
    zone = FakeDNS()
    names = [f"i{n}.example.net" for n in range(count)]
    zone.add("example.com", "TXT", [f"v=spf1 include:{names[0]} -all"])
    for index, name in enumerate(names):
        nxt = f" include:{names[index + 1]}" if index + 1 < len(names) else ""
        zone.add(name, "TXT", [f"v=spf1{nxt} ~all"])
    return zone


def test_lookup_count_follows_nested_includes():
    zone = _chain(4)
    count, problems = count_spf_lookups(
        zone.client(), "example.com", "v=spf1 include:i0.example.net -all"
    )
    assert count == 4
    assert problems == []


@pytest.mark.parametrize(
    ("lookups", "status"), [(8, Status.PASS), (10, Status.WARN), (11, Status.FAIL)]
)
def test_lookup_limit(lookups, status):
    finding = spf_findings(_chain(lookups))["SPF lookups"]
    assert finding.status is status
    assert finding.details["lookups"] == lookups


def test_a_mx_exists_count_as_lookups():
    zone = FakeDNS(
        {("example.com", "TXT"): ["v=spf1 a mx exists:%{i}.x.example.net ip4:192.0.2.1 -all"]}
    )
    assert spf_findings(zone)["SPF lookups"].details["lookups"] == 3


def test_missing_include_target_is_reported():
    zone = FakeDNS({("example.com", "TXT"): ["v=spf1 include:gone.example.net -all"]})
    finding = spf_findings(zone)["SPF lookups"]
    assert finding.status is Status.FAIL
    assert "no SPF record" in finding.message


def test_include_loop_is_detected():
    zone = FakeDNS(
        {
            ("example.com", "TXT"): ["v=spf1 include:a.example.net -all"],
            ("a.example.net", "TXT"): ["v=spf1 include:example.com ~all"],
        }
    )
    finding = spf_findings(zone)["SPF lookups"]
    assert "loop" in finding.message
    assert finding.status is Status.FAIL


def test_include_timeout_is_reported_not_raised():
    zone = FakeDNS(
        {
            ("example.com", "TXT"): ["v=spf1 include:slow.example.net -all"],
            ("slow.example.net", "TXT"): "timeout",
        }
    )
    finding = spf_findings(zone)["SPF lookups"]
    assert "timed out" in finding.message
    assert finding.status is Status.WARN
