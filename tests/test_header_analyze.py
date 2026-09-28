import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from deliv import header_analyze as ha
from deliv.cli import app
from deliv.lib.output import unstyle

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()


def checks(result):
    return {f["check"]: f for f in result["findings"]}


def test_parse_authentication_results_with_comments_and_quotes():
    header = ha.parse_authentication_results(
        "mx.example.net 1; spf=pass (domain of a@example.com; designates 192.0.2.1) "
        'smtp.mailfrom="a@example.com"; dkim=fail (body hash did not verify) header.d=example.com '
        "header.s=k1; dmarc=pass (p=REJECT) header.from=example.com; arc=none"
    )
    assert header.reporter == "mx.example.net"
    assert [r.method for r in header.results] == ["spf", "dkim", "dmarc", "arc"]
    spf = header.first("spf")
    assert spf.properties["smtp.mailfrom"] == "a@example.com"
    assert "designates" in spf.comment
    assert header.first("dkim").comment == "body hash did not verify"
    assert header.first("dmarc").properties["header.from"] == "example.com"
    assert header.first("missing") is None


def test_parse_authentication_results_none():
    assert ha.parse_authentication_results("mx.example.net; none").results == []


def test_parse_received():
    hop = ha.parse_received(
        "from o1.mail.example.com (o1.mail.example.com [192.0.2.25]) by mx.example.net "
        "with ESMTPS id x; Tue, 10 Mar 2026 09:00:04 -0700",
        1,
    )
    assert hop.from_host == "o1.mail.example.com"
    assert hop.from_ip == "192.0.2.25"
    assert hop.by_host == "mx.example.net"
    assert hop.date.startswith("Tue, 10 Mar 2026")
    ipv6 = ha.parse_received("from h (h [IPv6:2001:db8::5]) by mx; date", 2)
    assert ipv6.from_ip == "2001:db8::5"
    by_only = ha.parse_received("by 10.20.30.40 with SMTP id z; date", 3)
    assert by_only.from_host is None and by_only.from_ip is None


@pytest.mark.parametrize(
    ("ip", "external"),
    [
        ("192.0.2.25", True),
        ("10.0.0.12", False),
        ("192.168.1.2", False),
        ("::1", False),
        ("x", False),
    ],
)
def test_is_external_ip(ip, external):
    assert ha.is_external_ip(ip) is external


def test_aligned_pass_fixture():
    result = ha.analyze_file(FIXTURES / "aligned_pass.eml")
    assert result["verdict"] == "PASS"
    assert result["grade"] == "A"
    assert result["sending_ip"] == "192.0.2.25"
    assert result["sending_host"] == "o1.mail.example.com"
    alignment = result["alignment"]
    assert alignment["from_domain"] == "example.com"
    assert alignment["envelope_from_domain"] == "mail.example.com"
    assert alignment["spf_aligned"] and alignment["dkim_aligned"]
    assert alignment["dkim_domains"] == [{"domain": "example.com", "result": "pass"}]
    assert result["diagnosis"].startswith("Healthy")
    assert "SPF and DKIM" in checks(result)["Alignment"]["message"]


def test_esp_misaligned_fixture():
    result = ha.analyze_file(FIXTURES / "esp_misaligned.eml")
    assert result["verdict"] == "FAIL"
    c = checks(result)
    assert c["SPF"]["status"] == "pass"
    assert c["DKIM"]["status"] == "pass"
    assert c["DMARC"]["status"] == "fail"
    assert c["Alignment"]["status"] == "fail"
    assert "custom DKIM for example.com" in result["diagnosis"]
    assert "esp.example.net" in result["diagnosis"]


def test_forwarded_dkim_fail_fixture_uses_topmost_reporter():
    result = ha.analyze_file(FIXTURES / "forwarded_dkim_fail.eml")
    assert result["verdict"] == "FAIL"
    assert [h["reporter"] for h in result["auth_results"]] == [
        "mx.example.com",
        "relay.forwarder.example.net",
    ]
    assert result["sending_ip"] == "203.0.113.50"
    assert checks(result)["SPF"]["status"] == "warn"
    assert checks(result)["DKIM"]["status"] == "fail"
    assert "body hash" in result["diagnosis"]
    assert "203.0.113.50" in result["diagnosis"]


def _message(auth, extra=""):
    return (
        "Received: from s.example.com (s.example.com [192.0.2.9]) by mx.example.net; d\n"
        f"{auth}{extra}From: a@example.com\nSubject: t\n\nbody\n"
    ).encode()


def test_no_auth_results():
    result = ha.analyze_message(_message(""))
    assert checks(result)["Authentication-Results"]["status"] == "warn"
    assert "never checked" in checks(result)["Authentication-Results"]["message"]
    assert "Save the message" in result["diagnosis"]


def test_healthy_via_dkim_despite_spf_softfail():
    auth = (
        "Authentication-Results: mx.example.net; spf=softfail smtp.mailfrom=a@example.com; "
        "dkim=pass header.d=example.com; dmarc=pass header.from=example.com\n"
    )
    result = ha.analyze_message(_message(auth))
    assert result["verdict"] == "PASS"
    assert "forwarding" in result["diagnosis"]


def test_spf_fail_without_dkim_suggests_spoofing_or_missing_include():
    auth = (
        "Authentication-Results: mx.example.net; spf=fail smtp.mailfrom=a@example.com; "
        "dmarc=fail header.from=example.com\n"
    )
    result = ha.analyze_message(_message(auth))
    assert "192.0.2.9 is not listed" in result["diagnosis"]
    assert checks(result)["DKIM"]["message"] == "No DKIM signature was verified."


def test_spf_pass_unaligned_no_dkim():
    auth = "Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=b@esp.example.net\n"
    result = ha.analyze_message(_message(auth))
    assert "no DKIM signature" in result["diagnosis"]
    assert checks(result)["DMARC"]["status"] == "warn"


def test_dkim_signature_header_used_when_no_dkim_result():
    auth = "Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=a@example.com\n"
    result = ha.analyze_message(_message(auth, "DKIM-Signature: v=1; d=Example.com; s=k1; b=x\n"))
    assert result["alignment"]["dkim_domains"] == [
        {"domain": "example.com", "result": "unverified"}
    ]
    assert result["alignment"]["dmarc_would_pass"]


def test_generic_dkim_failure_diagnosis():
    auth = (
        "Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=b@esp.example.net; "
        "dkim=fail header.d=example.com; dmarc=fail header.from=example.com\n"
    )
    assert "DKIM verification failed" in ha.analyze_message(_message(auth))["diagnosis"]


def test_cli_human_and_json():
    result = runner.invoke(app, ["header-analyze", str(FIXTURES / "esp_misaligned.eml")])
    assert result.exit_code == 0, result.output
    text = unstyle(result.output)
    for label in (
        "Authentication results",
        "Received chain",
        "Sending IP: 198.51.100.77",
        "Alignment",
        "Diagnosis",
        "NOT ALIGNED",
    ):
        assert label in text
    data = json.loads(
        runner.invoke(app, ["header-analyze", str(FIXTURES / "aligned_pass.eml"), "--json"]).output
    )
    assert data["tool"] == "header-analyze" and data["verdict"] == "PASS"


def test_cli_missing_file():
    assert runner.invoke(app, ["header-analyze", "missing.eml"]).exit_code != 0


def test_alignment_message_distinguishes_failed_vs_misaligned():
    forwarded = checks(ha.analyze_file(FIXTURES / "forwarded_dkim_fail.eml"))["Alignment"]
    assert (
        "line up" in forwarded["message"] and "alignment itself is fine" in forwarded["remediation"]
    )
    esp = checks(ha.analyze_file(FIXTURES / "esp_misaligned.eml"))["Alignment"]
    assert esp["message"].startswith("Neither the SPF domain (esp.example.net)")
