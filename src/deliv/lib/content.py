"""Load email content from plain text, HTML, or ``.eml`` files into one shared structure.

``spam-scan`` and ``copy-check`` both need the visible text of a message, and ``copy-check`` also
needs its links, images, and (for ``.eml`` input) headers. This module parses each once, using only
the standard library.
"""

import re
import sys
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import Path

_HTML_SNIFF = re.compile(r"<\s*(html|body|div|p|table|td|a\s|img\s|br|span)\b", re.IGNORECASE)

_BLOCK_TAGS = frozenset(
    {
        "p", "div", "br", "tr", "table", "li", "ul", "ol", "h1", "h2", "h3", "h4", "h5", "h6",
        "section", "article", "header", "footer", "blockquote", "hr", "td", "th",
    }
)  # fmt: skip
#: Header names that, at the very start of stdin, mean the input is a raw message.
_EML_LEADING_HEADERS = (
    b"received:",
    b"return-path:",
    b"delivered-to:",
    b"mime-version:",
    b"message-id:",
    b"from:",
    b"date:",
    b"subject:",
)
_SKIP_TAGS = frozenset({"script", "style", "head", "title"})


@dataclass
class Link:
    """A hyperlink found in the message body."""

    href: str
    text: str = ""


@dataclass
class Image:
    """An image referenced by the message body."""

    src: str
    alt: str = ""


@dataclass
class EmailContent:
    """Everything the content tools need to know about one message.

    Attributes:
        source: Where the content came from (a file path, or ``"-"`` for stdin).
        source_format: ``"text"``, ``"html"``, or ``"eml"``.
        text: Visible text, with HTML tags removed and line breaks kept.
        html: The raw HTML body, when there is one.
        subject: The Subject header (``.eml`` input only).
        headers: Header name/value pairs (``.eml`` input only).
        links: Links found in the body.
        images: Images found in the body.
    """

    source: str
    source_format: str
    text: str
    html: str | None = None
    subject: str | None = None
    headers: list[tuple[str, str]] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    images: list[Image] = field(default_factory=list)

    @property
    def is_html(self) -> bool:
        """True when the body was HTML (tags were stripped to build :attr:`text`)."""
        return self.html is not None

    def header(self, name: str) -> str | None:
        """Return the first header named ``name`` (case-insensitive), or None."""
        wanted = name.lower()
        return next((value for key, value in self.headers if key.lower() == wanted), None)


class _HTMLExtractor(HTMLParser):
    """Collect visible text, links, and images from an HTML document in one pass."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[Link] = []
        self.images: list[Image] = []
        self._skip_depth = 0
        self._open_link: Link | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): value or "" for key, value in attrs}
        if tag in _SKIP_TAGS:
            self._skip_depth += 1
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")
        if tag == "a" and attributes.get("href"):
            self._open_link = Link(attributes["href"].strip())
            self.links.append(self._open_link)
        elif tag == "img":
            self.images.append(Image(attributes.get("src", ""), attributes.get("alt", "")))

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_TAGS and self._skip_depth:
            self._skip_depth -= 1
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")
        if tag == "a":
            self._open_link = None

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        self.parts.append(data)
        if self._open_link is not None:
            self._open_link.text = (self._open_link.text + " " + data.strip()).strip()


def _normalize_whitespace(text: str) -> str:
    lines = [" ".join(line.split()) for line in text.splitlines()]
    cleaned: list[str] = []
    for line in lines:
        if line or (cleaned and cleaned[-1]):
            cleaned.append(line)
    return "\n".join(cleaned).strip()


def parse_html(html: str) -> tuple[str, list[Link], list[Image]]:
    """Return ``(visible_text, links, images)`` for an HTML document."""
    extractor = _HTMLExtractor()
    extractor.feed(html)
    extractor.close()
    return _normalize_whitespace("".join(extractor.parts)), extractor.links, extractor.images


def html_to_text(html: str) -> str:
    """Strip tags from ``html`` and return its visible text with line breaks preserved."""
    return parse_html(html)[0]


_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


def text_links(text: str) -> list[Link]:
    """Find bare http(s) URLs in plain text."""
    return [Link(match.group(0).rstrip(".,;:!?")) for match in _URL_RE.finditer(text)]


def looks_like_html(text: str) -> bool:
    """Heuristically decide whether ``text`` is an HTML document."""
    return bool(_HTML_SNIFF.search(text[:5000]))


def from_string(raw: str, source: str = "-", force_format: str | None = None) -> EmailContent:
    """Build :class:`EmailContent` from text or HTML held in memory."""
    fmt = force_format or ("html" if looks_like_html(raw) else "text")
    if fmt == "html":
        text, links, images = parse_html(raw)
        links += [link for link in text_links(text) if link.href not in {x.href for x in links}]
        return EmailContent(source, "html", text, html=raw, links=links, images=images)
    return EmailContent(source, "text", raw.strip("\n"), links=text_links(raw))


def from_eml_bytes(raw: bytes, source: str = "-") -> EmailContent:
    """Parse an RFC 5322 message and pull out its body, subject, headers, links, and images."""
    message = BytesParser(policy=policy.default).parsebytes(raw)
    assert isinstance(message, EmailMessage)
    headers = [(key, str(value)) for key, value in message.items()]
    subject = str(message.get("Subject", "")) or None

    html_part = message.get_body(preferencelist=("html",))
    text_part = message.get_body(preferencelist=("plain",))
    if html_part is not None:
        content = from_string(html_part.get_content(), source, force_format="html")
    elif text_part is not None:
        content = from_string(text_part.get_content(), source, force_format="text")
    else:
        content = EmailContent(source, "text", "")
    content.source_format = "eml"
    content.subject = subject
    content.headers = headers
    return content


def load_content(path: str | Path) -> EmailContent:
    """Load a ``.txt``, ``.html``, or ``.eml`` file (or ``-`` for stdin) into :class:`EmailContent`.

    ``.eml`` files are parsed as full messages. Other files are sniffed: anything containing common
    HTML tags is treated as HTML.
    """
    source = str(path)
    if source == "-":
        data = sys.stdin.buffer.read()
        if data.lstrip()[:40].lower().startswith(_EML_LEADING_HEADERS):
            return from_eml_bytes(data, source)
        return from_string(data.decode("utf-8", errors="replace"), source)
    file_path = Path(path)
    data = file_path.read_bytes()
    if file_path.suffix.lower() == ".eml":
        return from_eml_bytes(data, source)
    return from_string(data.decode("utf-8", errors="replace"), source)
