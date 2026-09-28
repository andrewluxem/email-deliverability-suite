import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from deliv import report
from deliv.bounce_classify import classify_batch, classify_one
from deliv.cli import app
from deliv.copy_check import check_file
from deliv.dns_audit import audit_domain
from deliv.header_analyze import analyze_file
from deliv.spam_scan import scan_file
from deliv.warmup_plan import make_plan
from tests.dns_fixtures import healthy_fetcher, healthy_zone
from tests.fakes import FakeDNS

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()


@pytest.fixture
def results():
    zone = healthy_zone().add("_dmarc.example.com", "TXT", ["v=DMARC1; p=none"])
    return [
        make_plan("gmail", 50, 5_000, 15),
        scan_file(FIXTURES / "promo_spammy.html"),
        audit_domain("example.com", client=zone.client(), fetcher=healthy_fetcher()),
        check_file(FIXTURES / "promo_spammy.html"),
        analyze_file(FIXTURES / "esp_misaligned.eml"),
        classify_one("550 5.1.1 user unknown"),
        classify_batch(["452 4.2.2 mailbox full", "554 5.7.1 spam"]),
    ]


@pytest.fixture
def results_file(tmp_path, results):
    path = tmp_path / "results.json"
    path.write_text(json.dumps(results))
    return path


def test_build_report_orders_sections_and_fixes(results):
    model = report.build_report(results)
    tools = [s["tool"] for s in model["sections"]]
    assert tools[0] == "dns-audit"
    assert tools[-1] == "warmup-plan"
    statuses = [f["status"] for f in model["fixes"]]
    assert statuses == sorted(statuses, key=lambda s: 0 if s == "fail" else 1)
    assert model["fixes"][0]["priority"] == "P1"
    assert model["blocking"] >= 3 and model["to_review"] >= 1
    assert model["overall_grade"] in {"A", "B", "C", "D", "F"}


def test_fixes_within_severity_follow_tool_priority(results):
    fails = [f for f in report.build_report(results)["fixes"] if f["status"] == "fail"]
    order = {t: i for i, t in enumerate(report.TOOL_ORDER)}
    ranks = [order[f["tool"]] for f in fails]
    assert ranks == sorted(ranks)


def test_result_labels(results):
    labels = {r["tool"]: report.result_label(r) for r in results}
    assert labels["copy-check"] == "FAIL"
    assert labels["header-analyze"].endswith(", FAIL")
    assert labels["warmup-plan"] == "15 days"
    assert report.result_label(results[-1]) == "2 bounces"
    assert report.result_label(results[-2]) == "hard / suppress"


def test_markdown(results):
    md = report.render_markdown(report.build_report(results, "Q2 audit"))
    assert md.startswith("# Q2 audit")
    for section in (
        "## Executive summary",
        "## Prioritized fix list",
        "## DNS authentication audit: example.com",
        "## Warmup plan",
        "**Suggested rewrites**",
        "not a guarantee of inbox placement",
    ):
        assert section in md
    assert "1. **P1" in md


def test_markdown_escapes_pipes():
    item = make_plan("gmail", 50, 100, 2)
    item["summary"] = "a | b"
    assert "a \\| b" in report.render_markdown(report.build_report([item]))


def test_html_is_self_contained_and_escaped(results):
    results[3]["findings"][0]["message"] = "<script>alert(1)</script>"
    html = report.render_html(report.build_report(results))
    assert html.startswith("<!doctype html>")
    assert "<style>" in html
    assert "<script>alert" not in html and "&lt;script&gt;" in html
    for forbidden in ("<link", "<script", 'src="http', "@import", "url("):
        assert forbidden not in html
    assert "Prioritized fix list" in html and "prefers-color-scheme" in html


def test_all_pass_report_says_nothing_to_fix():
    item = audit_domain("example.com", client=healthy_zone().client(), fetcher=healthy_fetcher())
    model = report.build_report([item])
    assert model["fixes"] == []
    assert "Nothing to fix" in report.render_markdown(model)
    assert "Nothing to fix" in report.render_html(model)


def test_load_results_accepts_objects_arrays_and_wrappers(tmp_path, results):
    one = tmp_path / "one.json"
    one.write_text(json.dumps(results[0]))
    wrapped = tmp_path / "wrapped.json"
    wrapped.write_text(json.dumps({"results": results[1:3]}))
    mixed = tmp_path / "mixed.json"
    mixed.write_text(json.dumps([results[3], {"not": "a result"}]))
    loaded, warnings = report.load_results([one, wrapped, mixed])
    assert len(loaded) == 4
    assert len(warnings) == 1 and "skipped item 1" in warnings[0]


@pytest.mark.parametrize(
    ("content", "message"),
    [("{not json", "not valid JSON"), ("[]", "no deliv results"), ('{"tool": "x"}', "no deliv")],
)
def test_load_results_errors(tmp_path, content, message):
    path = tmp_path / "bad.json"
    path.write_text(content)
    with pytest.raises(report.ReportInputError, match=message):
        report.load_results([path])
    with pytest.raises(report.ReportInputError, match="not found"):
        report.load_results([tmp_path / "missing.json"])


def test_cli_markdown_to_stdout(results_file):
    result = runner.invoke(app, ["report", "--input", str(results_file)])
    assert result.exit_code == 0, result.output
    assert "# Email deliverability report" in result.output


def test_cli_html_to_file(results_file, tmp_path):
    out = tmp_path / "report.html"
    args = ["report", "-i", str(results_file), "--format", "html", "-o", str(out), "--title", "T"]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert out.read_text().startswith("<!doctype html>")


def test_cli_json_and_errors(results_file, tmp_path):
    data = json.loads(runner.invoke(app, ["report", "-i", str(results_file), "--json"]).output)
    assert data["tool"] == "report" and data["fixes"]
    bad = tmp_path / "bad.json"
    bad.write_text("nope")
    assert runner.invoke(app, ["report", "-i", str(bad)]).exit_code == 2


def test_end_to_end_via_cli_json(tmp_path, monkeypatch):
    """Every tool's --json output must be accepted by `deliv report`."""
    from deliv import blacklist, dns_audit

    zone = healthy_zone()
    monkeypatch.setattr(dns_audit, "DNSClient", lambda timeout, nameservers=None: zone.client())
    monkeypatch.setattr(dns_audit, "fetch_text", healthy_fetcher())
    monkeypatch.setattr(
        blacklist, "DNSClient", lambda timeout, nameservers=None: FakeDNS().client()
    )
    commands = [
        ["dns-audit", "example.com"],
        ["spam-scan", str(FIXTURES / "promo_spammy.html")],
        ["copy-check", str(FIXTURES / "newsletter_clean.html")],
        ["header-analyze", str(FIXTURES / "aligned_pass.eml")],
        ["bounce-classify", "5.1.1"],
        ["blacklist", "192.0.2.25", "--no-verify"],
        ["warmup-plan", "--target-volume", "1000"],
    ]
    outputs = []
    for args in commands:
        result = runner.invoke(app, [*args, "--json"])
        assert result.exit_code == 0, (args, result.output)
        outputs.append(json.loads(result.output))
    path = tmp_path / "all.json"
    path.write_text(json.dumps(outputs))
    result = runner.invoke(app, ["report", "-i", str(path), "-f", "html"])
    assert result.exit_code == 0, result.output
    assert result.output.count('<section class="card">') >= len(commands)
