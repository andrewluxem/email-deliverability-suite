import json

from typer.testing import CliRunner

from deliv import dns_audit
from deliv.cli import app
from deliv.lib.output import unstyle
from tests.dns_fixtures import healthy_fetcher, healthy_zone
from tests.fakes import FakeDNS, FakeFetcher

runner = CliRunner()


def by_check(result):
    return {f["check"]: f for f in result["findings"]}


def test_healthy_domain_gets_an_a():
    result = dns_audit.audit_domain(
        "Example.com", client=healthy_zone().client(), fetcher=healthy_fetcher()
    )
    assert result["tool"] == "dns-audit"
    assert result["target"] == "example.com"
    assert result["grade"] == "A"
    assert result["score"] == 100
    statuses = {f["status"] for f in result["findings"]}
    assert statuses <= {"pass", "info"}


def test_every_non_pass_finding_has_a_remediation():
    result = dns_audit.audit_domain(
        "bare.example.org", client=FakeDNS().client(), fetcher=FakeFetcher()
    )
    for finding in result["findings"]:
        if finding["status"] in {"warn", "fail"}:
            assert finding["remediation"], finding["check"]


def test_bare_domain_fails_with_f():
    result = dns_audit.audit_domain(
        "bare.example.org", client=FakeDNS().client(), fetcher=FakeFetcher()
    )
    checks = by_check(result)
    assert checks["SPF record"]["status"] == "fail"
    assert checks["DMARC record"]["status"] == "fail"
    assert checks["DKIM"]["status"] == "warn"
    assert result["grade"] == "F"


def test_typical_marketing_domain_grades_in_between():
    zone = healthy_zone()
    zone.add("_dmarc.example.com", "TXT", ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"])
    zone.add("_mta-sts.example.com", "TXT", [])
    zone.add("_smtp._tls.example.com", "TXT", [])
    zone.add("default._bimi.example.com", "TXT", [])
    result = dns_audit.audit_domain("example.com", client=zone.client(), fetcher=FakeFetcher())
    assert result["grade"] in {"B", "C"}
    assert by_check(result)["DMARC policy"]["status"] == "warn"


def test_custom_selector_is_probed_first():
    zone = healthy_zone()
    zone.add("k1._domainkey.example.com", "TXT", [])
    zone.add("esp2026._domainkey.example.com", "TXT", ["v=DKIM1; p=" + "A" * 392])
    result = dns_audit.audit_domain(
        "example.com", client=zone.client(), fetcher=healthy_fetcher(), selectors=["esp2026"]
    )
    dkim = by_check(result)["DKIM"]
    assert dkim["status"] == "pass"
    assert dkim["details"]["probed"][0] == "esp2026"


def test_timeouts_degrade_to_warnings_not_crashes():
    zone = FakeDNS()
    for name in ["example.com", "_dmarc.example.com", "_mta-sts.example.com"]:
        zone.add(name, "TXT", "timeout")
    result = dns_audit.audit_domain("example.com", client=zone.client(), fetcher=FakeFetcher())
    checks = by_check(result)
    assert checks["SPF record"]["status"] == "warn"
    assert "timed out" in checks["SPF record"]["message"]
    assert "--timeout" in checks["SPF record"]["remediation"]
    assert checks["DMARC record"]["status"] == "warn"


def test_cli_json_output(monkeypatch):
    zone = healthy_zone()
    monkeypatch.setattr(
        dns_audit,
        "DNSClient",
        lambda timeout, nameservers=None: zone.client(timeout),
    )
    monkeypatch.setattr(dns_audit, "fetch_text", healthy_fetcher())
    result = runner.invoke(app, ["dns-audit", "example.com", "--json", "--timeout", "3"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["grade"] == "A"
    assert zone.queries, "expected the fake resolver to be used"


def test_cli_human_output(monkeypatch):
    zone = healthy_zone()
    zone.add("_dmarc.example.com", "TXT", ["v=DMARC1; p=none"])
    monkeypatch.setattr(
        dns_audit, "DNSClient", lambda timeout, nameservers=None: zone.client(timeout)
    )
    monkeypatch.setattr(dns_audit, "fetch_text", healthy_fetcher())
    result = runner.invoke(app, ["dns-audit", "example.com"])
    assert result.exit_code == 0, result.output
    text = unstyle(result.output)
    assert "DNS authentication audit: example.com" in text
    assert "Grade" in text
    assert "fix:" in text
    assert "DMARC" in text


def test_help_is_marketer_readable():
    # CI forces rich color, which splits "--selector" with ANSI codes; compare plain text.
    result = runner.invoke(app, ["dns-audit", "--help"], env={"COLUMNS": "200"})
    assert result.exit_code == 0
    text = unstyle(result.output)
    assert "SPF" in text and "--selector" in text
