import json
import threading

from typer.testing import CliRunner

from deliv import blacklist as bl
from deliv.cli import app
from deliv.lib.output import unstyle
from tests.fakes import FakeDNS

runner = CliRunner()
IP = "192.0.2.25"
REV = "25.2.0.192"


class ThreadSafeFakeDNS(FakeDNS):
    def __init__(self, records=None):
        self._lock = threading.Lock()
        super().__init__(records)

    def __call__(self, name, rdtype, timeout):
        with self._lock:
            return super().__call__(name, rdtype, timeout)


def zone_with_test_points(**overrides):
    """All lists answer their test entries; the target is clean unless overridden."""
    fake = ThreadSafeFakeDNS()
    for b in bl.BLOCKLISTS:
        fake.add(bl.query_name(b.test_entry, b), "A", ["127.0.0.2"])
    for name, value in overrides.items():
        fake.add(name, "A", value)
    return fake


def statuses(result):
    return {r["name"]: r["status"] for r in result["results"]}


def test_query_names():
    zen = bl.BLOCKLISTS[0]
    assert bl.query_name(IP, zen) == f"{REV}.zen.spamhaus.org"
    dbl = next(b for b in bl.BLOCKLISTS if b.name == "Spamhaus DBL")
    assert bl.query_name("Mail.Example.com.", dbl) == "mail.example.com.dbl.spamhaus.org"


def test_lists_for_target_types():
    assert all(b.kind == "ip" for b in bl.lists_for(IP))
    assert all(b.kind == "domain" for b in bl.lists_for("example.com"))
    v6 = bl.lists_for("2001:db8::1")
    assert [b.name for b in v6] == ["Spamhaus ZEN"]


def test_required_lists_are_present_with_delisting_urls():
    names = {b.name for b in bl.BLOCKLISTS}
    assert {"Spamhaus ZEN", "Barracuda BRBL", "SpamCop", "SORBS"} <= names
    active_ip = [b for b in bl.BLOCKLISTS if b.kind == "ip" and not b.retired]
    assert len(active_ip) >= 6
    for b in bl.BLOCKLISTS:
        assert b.access
        if not b.retired:
            assert b.delist_url.startswith("https://")


def test_clean_ip():
    result = bl.check_target(IP, client=zone_with_test_points().client())
    assert result["listed_count"] == 0
    assert result["grade"] == "A"
    assert set(statuses(result).values()) == {"clean", "skipped"}
    assert statuses(result)["SORBS"] == "skipped"
    assert "Not listed on any of the 6 lists" in result["summary"]


def test_listed_ip_has_delisting_url():
    fake = zone_with_test_points(**{f"{REV}.bl.spamcop.net": ["127.0.0.2"]})
    result = bl.check_target(IP, client=fake.client())
    assert statuses(result)["SpamCop"] == "listed"
    finding = next(f for f in result["findings"] if f["check"] == "SpamCop")
    assert finding["status"] == "fail"
    assert "https://www.spamcop.net/bl.shtml" in finding["remediation"]
    assert result["listed_count"] == 1
    assert result["summary"].startswith("Listed on 1 of 6")


def test_spamhaus_public_resolver_refusal_is_an_error():
    fake = zone_with_test_points(**{f"{REV}.zen.spamhaus.org": ["127.255.255.254"]})
    result = bl.check_target(IP, client=fake.client())
    zen = next(r for r in result["results"] if r["name"] == "Spamhaus ZEN")
    assert zen["status"] == "error"
    assert "public or open resolver" in zen["message"]


def test_silent_refusal_is_caught_by_test_entry_verification():
    fake = zone_with_test_points(**{"2.0.0.127.zen.spamhaus.org": []})
    result = bl.check_target(IP, client=fake.client())
    assert statuses(result)["Spamhaus ZEN"] == "unverified"
    no_verify = bl.check_target(IP, client=fake.client(), verify=False)
    assert statuses(no_verify)["Spamhaus ZEN"] == "clean"


def test_mailspike_reputation_codes_are_not_listings():
    fake = zone_with_test_points(**{f"{REV}.bl.mailspike.net": ["127.0.0.13"]})
    assert statuses(bl.check_target(IP, client=fake.client()))["Mailspike BL"] == "clean"


def test_timeouts_and_failures_degrade_to_warnings():
    fake = zone_with_test_points(
        **{f"{REV}.b.barracudacentral.org": "timeout", f"{REV}.psbl.surriel.com": "servfail"}
    )
    result = bl.check_target(IP, client=fake.client())
    assert statuses(result)["Barracuda BRBL"] == "error"
    assert statuses(result)["PSBL"] == "error"
    warn = next(f for f in result["findings"] if f["check"] == "Barracuda BRBL")
    assert warn["status"] == "warn" and "--nameserver" in warn["remediation"]
    assert "could not give a trustworthy answer" in result["summary"]


def test_unexpected_exceptions_never_crash():
    def exploding(name, rdtype, timeout):
        raise ValueError("boom")

    from deliv.lib.dns import DNSClient

    result = bl.check_target(IP, client=DNSClient(backend=exploding))
    assert {r["status"] for r in result["results"]} == {"error", "skipped"}


def test_domain_lists_and_uribl_refusal():
    fake = zone_with_test_points(
        **{
            "example.com.dbl.spamhaus.org": ["127.0.1.2"],
            "example.com.multi.uribl.com": ["127.0.0.1"],
        }
    )
    result = bl.check_target("Example.com", client=fake.client())
    assert result["target"] == "example.com" and result["target_type"] == "domain"
    s = statuses(result)
    assert s == {"Spamhaus DBL": "listed", "SURBL": "clean", "URIBL": "error"}


def test_include_retired_queries_sorbs():
    result = bl.check_target(IP, client=zone_with_test_points().client(), include_retired=True)
    assert statuses(result)["SORBS"] == "clean"


def test_cli(monkeypatch):
    fake = zone_with_test_points(**{f"{REV}.zen.spamhaus.org": ["127.0.0.3"]})
    monkeypatch.setattr(bl, "DNSClient", lambda timeout, nameservers=None: fake.client(timeout))
    result = runner.invoke(app, ["blacklist", IP, "--timeout", "2"])
    assert result.exit_code == 0, result.output
    text = unstyle(result.output)
    assert "Blocklist check: 192.0.2.25 (ip)" in text
    assert "LISTED" in text and "Delisting" in text and "https://check.spamhaus.org/" in text
    data = json.loads(runner.invoke(app, ["blacklist", "example.com", "--json"]).output)
    assert data["tool"] == "blacklist" and data["target_type"] == "domain"
    assert "Tip:" in unstyle(runner.invoke(app, ["blacklist", "example.com"]).output)
