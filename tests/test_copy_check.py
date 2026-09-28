import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from deliv import copy_check
from deliv.cli import app
from deliv.lib.content import from_eml_bytes, from_string
from deliv.lib.output import unstyle
from deliv.lib.scoring import Status

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()

FOOTER = (
    '<p><a href="https://www.example.com/unsubscribe">Unsubscribe</a> '
    "Example Co., 500 Market Street, Springfield, IL 62701</p>"
)
BODY = " ".join(["We wrote a practical guide to planning your spring trips with the family."] * 8)


def html(body=BODY, footer=FOOTER, extra=""):
    return from_string(f"<html><body><p>{body}</p>{extra}{footer}</body></html>", "t.html")


def checks(result):
    return {f["check"]: f for f in result["findings"]}


# --- verdicts and exit codes -------------------------------------------------


def test_clean_newsletter_passes():
    result = copy_check.check_file(FIXTURES / "newsletter_clean.html")
    assert result["verdict"] == "PASS", result["reasons"]
    assert result["exit_code"] == 0
    assert result["reasons"] == ["Every pre-send check passed."]


def test_spammy_promo_fails():
    result = copy_check.check_file(FIXTURES / "promo_spammy.html")
    assert result["verdict"] == "FAIL"
    assert result["exit_code"] == 2
    assert any(r.startswith("Link shorteners") for r in result["reasons"])
    assert any(r.startswith("Unsubscribe link") for r in result["reasons"])
    assert result["rewrites"]


def test_missing_address_needs_review():
    result = copy_check.check_content(
        html(footer='<a href="https://x.example.com/unsubscribe">u</a>')
    )
    assert result["verdict"] == "REVIEW"
    assert result["exit_code"] == 1
    assert result["reasons"][0].startswith("Physical address")


def test_fail_reasons_are_listed_before_review_reasons():
    content = html(footer="<p>Example Co., 500 Market Street</p>", body=BODY + " Hello!!")
    reasons = copy_check.check_content(content)["reasons"]
    assert reasons[0].startswith("Unsubscribe link")
    assert any(r.startswith("Punctuation") for r in reasons[1:])


@pytest.mark.parametrize(
    ("fixture", "code"),
    [("newsletter_clean.html", 0), ("promo_spammy.html", 2), ("copy_one_click.eml", 0)],
)
def test_cli_exit_codes(fixture, code):
    result = runner.invoke(app, ["copy-check", str(FIXTURES / fixture)])
    assert result.exit_code == code, result.output


def test_cli_review_exit_code(tmp_path):
    page = tmp_path / "review.html"
    page.write_text(f'<p>{BODY}</p><a href="https://example.com/unsubscribe">Unsubscribe</a>')
    assert runner.invoke(app, ["copy-check", str(page)]).exit_code == 1


def test_cli_json_keeps_exit_code():
    result = runner.invoke(app, ["copy-check", str(FIXTURES / "promo_spammy.html"), "--json"])
    assert result.exit_code == 2
    data = json.loads(result.output)
    assert data["verdict"] == "FAIL" and data["exit_code"] == 2 and data["tool"] == "copy-check"


def test_cli_missing_file_is_exit_3():
    result = runner.invoke(app, ["copy-check", "missing.html"])
    assert result.exit_code == 3


def test_cli_report_reads_like_qa():
    result = runner.invoke(app, ["copy-check", str(FIXTURES / "promo_spammy.html")])
    text = unstyle(result.output)
    assert "Pre-send QA report" in text
    assert "Verdict:  FAIL" in text
    assert "Why" in text and "Checklist" in text and "Copy fixes" in text
    assert "fix:" in text


# --- individual checks -------------------------------------------------------


def test_shorteners_detected_in_html_and_text():
    finding = copy_check.check_shorteners(from_string("Go to https://bit.ly/abc or tinyurl.com/x"))
    assert finding.status is Status.FAIL
    assert finding.details["links"] == ["https://bit.ly/abc"]
    content = html(
        extra='<a href="https://www.t.co/x">x</a><a href="https://bit.ly.example.com">y</a>'
    )
    assert copy_check.check_shorteners(content).details["links"] == ["https://www.t.co/x"]


@pytest.mark.parametrize(
    ("text", "status"),
    [
        ("This is a normal sentence about our spring guide and trail maps.", Status.PASS),
        ("THIS IS A NORMAL sentence about our spring guide and trail maps today.", Status.WARN),
        ("THIS IS ALL SHOUTING ABOUT OUR SPRING GUIDE AND TRAIL MAPS", Status.FAIL),
        ("TOO SHORT", Status.INFO),
    ],
)
def test_capitalization(text, status):
    assert copy_check.check_capitalization(from_string(text)).status is status


@pytest.mark.parametrize(
    ("text", "status"),
    [
        (BODY, Status.PASS),
        (BODY + " Great!", Status.PASS),
        (BODY + " Wow!!", Status.WARN),
        ("Hi! " + BODY + " Now! Yes!", Status.WARN),
        ("Buy! Now! Today! Yes! Really!", Status.FAIL),
    ],
)
def test_punctuation(text, status):
    assert copy_check.check_punctuation(from_string(text)).status is status


def test_images():
    ratio, alt = copy_check.check_images(html(extra='<img src="a.png" alt="A">'))
    assert ratio.status is Status.PASS and alt.status is Status.PASS
    ratio, alt = copy_check.check_images(html(body="Short.", extra='<img src="a.png">'))
    assert ratio.status is Status.FAIL and alt.status is Status.WARN
    many = "".join(f'<img src="{i}.png" alt="x">' for i in range(3))
    ratio, _ = copy_check.check_images(html(extra=many))
    assert ratio.status is Status.WARN
    pixel = '<img src="https://t.example.com/open/abc.gif" width="1">'
    (ratio,) = copy_check.check_images(html(extra=pixel))
    assert ratio.status is Status.PASS and ratio.details == {}
    (plain,) = copy_check.check_images(from_string("plain text"))
    assert plain.status is Status.INFO


def test_html_size():
    assert copy_check.check_html_size(from_string("plain")) is None
    assert copy_check.check_html_size(html()).status is Status.PASS
    big = html(extra="<p>" + "x" * (110 * 1024) + "</p>")
    assert copy_check.check_html_size(big).status is Status.WARN


def _eml(headers):
    return from_eml_bytes(
        (headers + "Subject: Hi there\r\nContent-Type: text/html\r\n\r\n<p>Body</p>").encode()
    )


def test_list_unsubscribe_headers():
    assert copy_check.check_list_unsubscribe(html()).status is Status.INFO
    assert copy_check.check_list_unsubscribe(_eml("")).status is Status.FAIL
    mailto_only = _eml("List-Unsubscribe: <mailto:u@example.com>\r\n")
    assert copy_check.check_list_unsubscribe(mailto_only).status is Status.WARN
    one_click = _eml(
        "List-Unsubscribe: <https://example.com/u>\r\n"
        "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
    )
    assert copy_check.check_list_unsubscribe(one_click).status is Status.PASS


@pytest.mark.parametrize(
    "footer",
    [
        '<a href="https://example.com/prefs">Manage email preferences</a>',
        '<a href="https://example.com/opt-out?u=1">here</a>',
        '<a href="{{unsubscribe_url}}">Leave</a>',
        "<p>*|UNSUB|*</p>",
        "<p>%%unsubscribe_link%%</p>",
    ],
)
def test_unsubscribe_link_variants(footer):
    assert copy_check.check_unsubscribe_link(html(footer=footer)).status is Status.PASS


def test_unsubscribe_link_missing_and_plain_text():
    assert copy_check.check_unsubscribe_link(html(footer="")).status is Status.FAIL
    text = from_string("Stop receiving these: unsubscribe at https://example.com/u")
    assert copy_check.check_unsubscribe_link(text).status is Status.PASS


@pytest.mark.parametrize(
    "address",
    [
        "Example Co., 500 Market Street, Springfield",
        "PO Box 1234, Springfield",
        "Springfield, IL 62701",
        "10 Downing St, London SW1A 2AA",
        "Toronto, ON M5V 3L9",
        "{{ organization.address }}",
        "*|LIST:ADDRESSLINE|*",
    ],
)
def test_physical_address_variants(address):
    content = html(footer=f"<p>{address}</p>")
    assert copy_check.check_physical_address(content).status is Status.PASS


def test_physical_address_missing():
    assert copy_check.check_physical_address(html(footer="<p>Thanks!</p>")).status is Status.WARN


def test_subject_checks():
    assert copy_check.check_subject(html()) is None
    assert copy_check.check_subject(from_eml_bytes(b"Subject: \r\n\r\nx")).status is Status.FAIL
    loud = from_eml_bytes(b"Subject: HUGE SPRING SALE STARTS NOW\r\n\r\nx")
    assert copy_check.check_subject(loud).status is Status.WARN
    long = from_eml_bytes(b"Subject: " + b"a" * 80 + b"\r\n\r\nx")
    assert copy_check.check_subject(long).status is Status.WARN
    ok = from_eml_bytes(b"Subject: Your trail guide\r\n\r\nx")
    assert copy_check.check_subject(ok).status is Status.PASS


def test_eml_fixture_uses_headers():
    result = copy_check.check_file(FIXTURES / "copy_one_click.eml")
    assert result["input_format"] == "eml"
    assert checks(result)["List-Unsubscribe header"]["status"] == "pass"
    assert checks(result)["Subject line"]["status"] == "pass"
