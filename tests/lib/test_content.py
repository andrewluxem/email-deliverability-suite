import io
import sys
from pathlib import Path

from deliv.lib.content import (
    from_eml_bytes,
    from_string,
    html_to_text,
    load_content,
    looks_like_html,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_html_to_text_skips_head_and_keeps_lines():
    text = html_to_text(
        "<html><head><style>p{}</style></head><body><p>One</p><p>Two &amp; three</p>"
    )
    assert text.splitlines() == ["One", "", "Two & three"]


def test_from_string_extracts_links_and_images():
    content = from_string(
        '<p><a href="https://x.example.com/a">Go <b>now</b></a> <img src="i.png" alt="i"></p>'
    )
    assert content.is_html
    assert content.links[0].href == "https://x.example.com/a"
    assert content.links[0].text == "Go now"
    assert content.images[0].src == "i.png"


def test_plain_text_links():
    content = from_string("See https://example.com/a, then https://example.org/b.")
    assert not content.is_html
    assert [link.href for link in content.links] == [
        "https://example.com/a",
        "https://example.org/b",
    ]


def test_looks_like_html():
    assert looks_like_html("<div>hi</div>")
    assert not looks_like_html("Price < 5 and > 2")


def test_eml_prefers_html_part():
    raw = (
        b"From: News <news@example.com>\r\nTo: a@example.net\r\nSubject: Hello there\r\n"
        b"List-Unsubscribe: <https://example.com/u>\r\nMIME-Version: 1.0\r\n"
        b'Content-Type: multipart/alternative; boundary="b"\r\n\r\n'
        b"--b\r\nContent-Type: text/plain\r\n\r\nPlain body\r\n"
        b"--b\r\nContent-Type: text/html\r\n\r\n<p>HTML body</p>\r\n--b--\r\n"
    )
    content = from_eml_bytes(raw, "msg.eml")
    assert content.source_format == "eml"
    assert content.is_html
    assert content.text == "HTML body"
    assert content.subject == "Hello there"
    assert content.header("list-unsubscribe") == "<https://example.com/u>"
    assert content.header("x-missing") is None


def test_eml_plain_only_and_empty():
    content = from_eml_bytes(b"Subject: Hi\r\n\r\nJust text\r\n")
    assert not content.is_html and content.text.strip() == "Just text"
    empty = from_eml_bytes(b"Subject: Hi\r\nContent-Type: image/png\r\n\r\nxx")
    assert empty.text == ""


def test_load_content_from_files(tmp_path):
    html = load_content(FIXTURES / "newsletter_clean.html")
    assert html.source_format == "html"
    txt = tmp_path / "copy.txt"
    txt.write_text("Hello\nWorld\n")
    assert load_content(txt).text == "Hello\nWorld"


def test_load_content_from_stdin(monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"Subject: Hi\n\nBody text\n")))
    content = load_content("-")
    assert content.source_format == "eml"
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"Just some copy")))
    assert load_content("-").text == "Just some copy"
