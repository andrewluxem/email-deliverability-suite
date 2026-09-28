from deliv.checks.dkim import DEFAULT_DKIM_SELECTORS, check_dkim, estimate_rsa_bits
from deliv.lib.scoring import Status
from tests.dns_fixtures import KEY_512, KEY_1024, KEY_2048
from tests.fakes import FakeDNS


def run(zone, selectors=DEFAULT_DKIM_SELECTORS):
    (finding,) = check_dkim(zone.client(), "example.com", selectors)
    return finding


def test_key_size_estimates():
    assert estimate_rsa_bits(KEY_2048) == 2048
    assert estimate_rsa_bits(KEY_1024) == 1024
    assert estimate_rsa_bits(KEY_512) == 512
    assert estimate_rsa_bits("not base64!!") is None


def test_finds_known_selectors():
    zone = FakeDNS(
        {
            ("google._domainkey.example.com", "TXT"): [f"v=DKIM1; k=rsa; p={KEY_2048}"],
            ("selector2._domainkey.example.com", "TXT"): [f"p={KEY_2048}"],
        }
    )
    finding = run(zone)
    assert finding.status is Status.PASS
    assert set(finding.details["found"]) == {"google", "selector2"}


def test_ed25519_key_passes():
    zone = FakeDNS({("k2._domainkey.example.com", "TXT"): ["v=DKIM1; k=ed25519; p=abc="]})
    assert run(zone).status is Status.PASS


def test_short_keys():
    zone = FakeDNS({("k1._domainkey.example.com", "TXT"): [f"v=DKIM1; p={KEY_1024}"]})
    assert run(zone).status is Status.WARN
    zone = FakeDNS({("k1._domainkey.example.com", "TXT"): [f"v=DKIM1; p={KEY_512}"]})
    assert run(zone).status is Status.FAIL


def test_none_found_suggests_selector_flag():
    finding = run(FakeDNS())
    assert finding.status is Status.WARN
    assert "--selector" in finding.remediation


def test_revoked_key_and_non_dkim_records_are_ignored():
    zone = FakeDNS(
        {
            ("default._domainkey.example.com", "TXT"): ["v=DKIM1; p="],
            ("dkim._domainkey.example.com", "TXT"): ["some other record"],
        }
    )
    finding = run(zone)
    assert finding.status is Status.WARN
    assert "revoked" in finding.message


def test_lookup_errors_warn():
    zone = FakeDNS({("k1._domainkey.example.com", "TXT"): "servfail"})
    finding = run(zone, ["k1"])
    assert finding.status is Status.WARN
    assert "Could not check" in finding.message
