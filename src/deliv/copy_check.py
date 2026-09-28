"""``deliv copy-check``: the pre-send QA gate.

Runs ``spam-scan`` and a set of pre-send checks a deliverability team would otherwise do by hand:
link shorteners, shouting, punctuation, image-to-text balance, alt text, Gmail clipping, the
List-Unsubscribe headers, a visible unsubscribe link, and a physical mailing address. It returns
one verdict with the reasons behind it:

* ``PASS`` (exit code 0): nothing to fix.
* ``REVIEW`` (exit code 1): warnings a human should look at before sending.
* ``FAIL`` (exit code 2): at least one problem that should block the send.

Exit code 3 means the input could not be read, so a pipeline never mistakes it for a verdict.

The exit codes make it drop-in usable as a CI step or ESP pre-flight hook.
"""

import re
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlparse

import typer

from deliv.lib.content import EmailContent, load_content
from deliv.lib.options import JsonFlag
from deliv.lib.output import emit, envelope, grade_badge, heading, render_findings, subheading
from deliv.lib.scoring import Finding, Status, worst_status
from deliv.spam_scan import load_triggers, scan_content

VERDICTS = {Status.PASS: "PASS", Status.WARN: "REVIEW", Status.FAIL: "FAIL"}
EXIT_CODES = {"PASS": 0, "REVIEW": 1, "FAIL": 2}
#: Exit code when the input file cannot be read (kept distinct from FAIL on purpose).
INPUT_ERROR_EXIT_CODE = 3

#: Public link-shortening domains. Spam filters distrust them because they hide the destination.
URL_SHORTENERS = frozenset(
    {
        "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
        "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "bl.ink", "t.ly", "s.id",
        "lnkd.in", "v.gd", "soo.gd", "qrco.de", "shorte.st", "adf.ly", "clck.ru", "tiny.one",
        "short.io", "urlz.fr", "x.co", "u.to", "trib.al", "dlvr.it",
    }
)  # fmt: skip

#: Gmail clips HTML bodies larger than roughly this many bytes, hiding the footer.
GMAIL_CLIP_BYTES = 102 * 1024

SPAM_PASS_SCORE = 80
SPAM_FAIL_SCORE = 60
CAPS_WARN_RATIO = 0.15
CAPS_FAIL_RATIO = 0.30
EXCLAIM_WARN_PER_100 = 1.0
EXCLAIM_FAIL_PER_100 = 3.0
WORDS_PER_IMAGE_WARN = 60
MIN_WORDS_WITH_IMAGES = 50
SUBJECT_MAX_CHARS = 70

_UNSUB_WORDS = re.compile(
    r"unsubscribe|opt[\s-]?out|manage (?:your )?(?:email )?preferences|email preferences|"
    r"update (?:your )?preferences|stop receiving",
    re.IGNORECASE,
)
#: ESP merge tags that render an unsubscribe link at send time.
_UNSUB_MERGE_TAGS = re.compile(
    r"\{\{\s*[^}]*unsub[^}]*\}\}|\*\|UNSUB\|\*|%%[^%]*unsub[^%]*%%|\[\s*unsubscribe[^\]]*\]|"
    r"\$\{?unsubscribe|<%[^%]*unsub[^%]*%>|\{\$?unsubscribe[^}]*\}",
    re.IGNORECASE,
)
_ADDRESS_PATTERNS = (
    re.compile(
        r"\b\d{1,6}\s+(?:[A-Za-z0-9.'-]+\s+){0,5}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|"
        r"Lane|Ln|Drive|Dr|Way|Court|Ct|Place|Pl|Parkway|Pkwy|Highway|Hwy|Square|Sq|Terrace|"
        r"Circle|Cir|Plaza)\b\.?",
        re.IGNORECASE,
    ),
    re.compile(r"\bP\.?\s?O\.?\s+Box\s+\d+", re.IGNORECASE),
    re.compile(r"\b[A-Z]{2}\s+\d{5}(?:-\d{4})?\b"),  # US state + ZIP
    re.compile(r"\b[A-Z]{1,2}\d[A-Z\d]?\s+\d[A-Z]{2}\b"),  # UK postcode
    re.compile(r"\b[A-Z]\d[A-Z]\s?\d[A-Z]\d\b"),  # Canadian postal code
)
_ADDRESS_MERGE_TAGS = re.compile(
    r"\{\{[^}]*address[^}]*\}\}|\*\|[^|]*ADDRESS[^|]*\|\*|%%[^%]*address[^%]*%%|"
    r"\[[^\]]*address[^\]]*\]|\{\$?[^}]*address[^}]*\}",
    re.IGNORECASE,
)


def _host(url: str) -> str:
    try:
        host = urlparse(url if "://" in url else f"https://{url}").hostname or ""
    except ValueError:
        return ""
    return host.lower().removeprefix("www.")


def check_spam_score(content: EmailContent) -> tuple[Finding, dict[str, Any]]:
    """Run spam-scan and turn its score into a gate finding."""
    spam = scan_content(content, load_triggers())
    score, letter = spam["score"], spam["grade"]
    top = spam["rewrites"][0] if spam["rewrites"] else None
    hint = f'Start with "{top["found"]}": {top["rewrite"]}' if top else None
    details = {"score": score, "grade": letter}
    if score >= SPAM_PASS_SCORE:
        finding = Finding(
            "Spam score",
            Status.PASS,
            f"Spam-risk grade {letter} ({score}/100). {spam['summary']}",
            hint,
            "Content",
            details=details,
        )
    elif score >= SPAM_FAIL_SCORE:
        finding = Finding(
            "Spam score",
            Status.WARN,
            f"Spam-risk grade {letter} ({score}/100). {spam['summary']}",
            hint,
            "Content",
            details=details,
        )
    else:
        finding = Finding(
            "Spam score",
            Status.FAIL,
            f"Spam-risk grade {letter} ({score}/100): copy is likely to be filtered.",
            hint,
            "Content",
            details=details,
        )
    return finding, spam


def check_shorteners(content: EmailContent) -> Finding:
    """Flag links that go through public URL shorteners."""
    shortened = sorted({link.href for link in content.links if _host(link.href) in URL_SHORTENERS})
    if shortened:
        listed = ", ".join(shortened[:5])
        return Finding(
            "Link shorteners",
            Status.FAIL,
            f"{len(shortened)} shortened link(s) hide their destination: {listed}.",
            "Link directly to your own domain (use your ESP's click tracking or a branded "
            "link domain instead of a public shortener).",
            "Links",
            details={"links": shortened},
        )
    return Finding(
        "Link shorteners",
        Status.PASS,
        f"No public URL shorteners among {len(content.links)} link(s).",
        None,
        "Links",
    )


def check_capitalization(content: EmailContent) -> Finding:
    """Measure the share of letters that are upper case."""
    letters = [c for c in content.text if c.isalpha()]
    if len(letters) < 40:
        return Finding(
            "Capitalization",
            Status.INFO,
            "Too little text to judge capitalization.",
            None,
            "Content",
            weight=0,
        )
    ratio = sum(c.isupper() for c in letters) / len(letters)
    details = {"uppercase_ratio": round(ratio, 3)}
    message = f"{ratio:.0%} of letters are capitals."
    if ratio >= CAPS_FAIL_RATIO:
        return Finding(
            "Capitalization",
            Status.FAIL,
            message + " That reads as shouting to filters and readers.",
            "Rewrite in sentence case; use headings and bold for emphasis.",
            "Content",
            details=details,
        )
    if ratio >= CAPS_WARN_RATIO:
        return Finding(
            "Capitalization",
            Status.WARN,
            message + " That is on the high side.",
            "Cut all-caps words and headlines back to sentence case.",
            "Content",
            details=details,
        )
    return Finding("Capitalization", Status.PASS, message, None, "Content", details=details)


def check_punctuation(content: EmailContent) -> Finding:
    """Check exclamation-mark density and runs like ``!!`` or ``??``."""
    words = max(1, len(content.text.split()))
    exclaims = content.text.count("!")
    per_100 = 100 * exclaims / words
    runs = re.findall(r"[!?]{2,}", content.text)
    details = {"exclamations": exclaims, "per_100_words": round(per_100, 2), "runs": runs[:10]}
    if per_100 > EXCLAIM_FAIL_PER_100:
        return Finding(
            "Punctuation",
            Status.FAIL,
            f"{exclaims} exclamation marks ({per_100:.1f} per 100 words).",
            "Keep it to one exclamation mark per email, at most.",
            "Content",
            details=details,
        )
    if per_100 > EXCLAIM_WARN_PER_100 or runs:
        extra = f" Repeated marks: {' '.join(runs[:3])}." if runs else ""
        return Finding(
            "Punctuation",
            Status.WARN,
            f"{exclaims} exclamation marks ({per_100:.1f} per 100 words).{extra}",
            "Remove repeated !! / ?? and most exclamation marks.",
            "Content",
            details=details,
        )
    return Finding(
        "Punctuation",
        Status.PASS,
        f"{exclaims} exclamation mark(s); punctuation looks calm.",
        None,
        "Content",
        details=details,
    )


def check_images(content: EmailContent) -> list[Finding]:
    """Check image-to-text balance and alt text (HTML input only)."""
    if not content.is_html:
        return [
            Finding(
                "Image-to-text ratio",
                Status.INFO,
                "Plain-text input: no images to check.",
                None,
                "Layout",
                weight=0,
            )
        ]
    images = [img for img in content.images if img.src and not _is_tracking_pixel(img.src)]
    words = len(content.text.split())
    details = {"images": len(images), "words": words}
    if not images:
        ratio = Finding(
            "Image-to-text ratio", Status.PASS, f"No images; {words} words of text.", None, "Layout"
        )
    elif words < MIN_WORDS_WITH_IMAGES:
        ratio = Finding(
            "Image-to-text ratio",
            Status.FAIL,
            f"{len(images)} image(s) but only {words} words: this reads as an image-only email.",
            "Put the message in live HTML text; aim for at least 60 words per image.",
            "Layout",
            details=details,
        )
    elif (per_image := words / len(images)) < WORDS_PER_IMAGE_WARN:
        ratio = Finding(
            "Image-to-text ratio",
            Status.WARN,
            f"{len(images)} image(s) for {words} words ({per_image:.0f} words per image).",
            "Add live text or cut images; aim for at least 60 words per image.",
            "Layout",
            details=details,
        )
    else:
        ratio = Finding(
            "Image-to-text ratio",
            Status.PASS,
            f"{len(images)} image(s) for {words} words ({per_image:.0f} words per image).",
            None,
            "Layout",
            details=details,
        )

    if not images:
        return [ratio]
    missing_alt = [img.src for img in images if not img.alt.strip()]
    if missing_alt:
        alt = Finding(
            "Image alt text",
            Status.WARN,
            f"{len(missing_alt)} of {len(images)} image(s) have no alt text.",
            "Add short, descriptive alt text; many inboxes block images by default.",
            "Layout",
            details={"missing": missing_alt[:10]},
        )
    else:
        alt = Finding("Image alt text", Status.PASS, "Every image has alt text.", None, "Layout")
    return [ratio, alt]


def _is_tracking_pixel(src: str) -> bool:
    lowered = src.lower()
    return any(token in lowered for token in ("/open", "pixel", "track", "beacon", "/o.gif"))


def check_html_size(content: EmailContent) -> Finding | None:
    """Warn when the HTML body is big enough for Gmail to clip it."""
    if not content.html:
        return None
    size = len(content.html.encode("utf-8"))
    details = {"bytes": size, "limit": GMAIL_CLIP_BYTES}
    if size > GMAIL_CLIP_BYTES:
        return Finding(
            "Message size",
            Status.WARN,
            f"HTML is {size / 1024:.1f} KB; Gmail clips anything over 102 KB, hiding the footer "
            "and unsubscribe link.",
            "Minify the HTML, inline less CSS, or trim content.",
            "Layout",
            details=details,
        )
    return Finding(
        "Message size",
        Status.PASS,
        f"HTML is {size / 1024:.1f} KB, under Gmail's 102 KB clipping limit.",
        None,
        "Layout",
        details=details,
    )


def check_list_unsubscribe(content: EmailContent) -> Finding:
    """Check the List-Unsubscribe and one-click List-Unsubscribe-Post headers (``.eml`` only)."""
    if content.source_format != "eml":
        return Finding(
            "List-Unsubscribe header",
            Status.INFO,
            "Not checkable from an HTML/text file: headers are added at send time.",
            "Confirm your ESP adds List-Unsubscribe and List-Unsubscribe-Post (one-click); Gmail "
            "and Yahoo require both for bulk senders. Run copy-check on a test .eml to verify.",
            "Compliance",
            weight=0,
        )
    header = content.header("List-Unsubscribe")
    post = content.header("List-Unsubscribe-Post") or ""
    details = {"list_unsubscribe": header, "list_unsubscribe_post": post or None}
    if not header:
        return Finding(
            "List-Unsubscribe header",
            Status.FAIL,
            "No List-Unsubscribe header, so inboxes cannot show their unsubscribe button.",
            "Turn on List-Unsubscribe in your ESP (with an https URL and one-click POST support).",
            "Compliance",
            details=details,
        )
    has_https = "<https://" in header.lower()
    if has_https and "list-unsubscribe=one-click" in post.lower():
        return Finding(
            "List-Unsubscribe header",
            Status.PASS,
            "List-Unsubscribe with one-click (RFC 8058) is present.",
            None,
            "Compliance",
            details=details,
        )
    return Finding(
        "List-Unsubscribe header",
        Status.WARN,
        "List-Unsubscribe is present but not one-click (RFC 8058).",
        "Add an https:// unsubscribe URL and 'List-Unsubscribe-Post: List-Unsubscribe=One-Click'.",
        "Compliance",
        details=details,
    )


def check_unsubscribe_link(content: EmailContent) -> Finding:
    """Look for a visible unsubscribe or preferences link (or an ESP merge tag for one)."""
    for link in content.links:
        if _UNSUB_WORDS.search(link.text) or _UNSUB_WORDS.search(link.href):
            return Finding(
                "Unsubscribe link",
                Status.PASS,
                f"Unsubscribe link found ({link.text or link.href}).",
                None,
                "Compliance",
            )
    raw = content.html or content.text
    if _UNSUB_MERGE_TAGS.search(raw):
        return Finding(
            "Unsubscribe link",
            Status.PASS,
            "Unsubscribe merge tag found; your ESP fills in the link at send time.",
            None,
            "Compliance",
        )
    if not content.is_html and _UNSUB_WORDS.search(content.text) and content.links:
        return Finding(
            "Unsubscribe link",
            Status.PASS,
            "Unsubscribe instructions and a link found in the text.",
            None,
            "Compliance",
        )
    return Finding(
        "Unsubscribe link",
        Status.FAIL,
        "No visible unsubscribe link in the body.",
        "Add an 'Unsubscribe' link to the footer. CAN-SPAM, CASL, and GDPR all expect one, and "
        "people who cannot find it hit 'Report spam' instead.",
        "Compliance",
    )


def check_physical_address(content: EmailContent) -> Finding:
    """Look for a postal address (or an ESP address merge tag) in the footer."""
    raw = content.html or content.text
    if _ADDRESS_MERGE_TAGS.search(raw):
        return Finding(
            "Physical address",
            Status.PASS,
            "Address merge tag found; your ESP inserts the postal address at send time.",
            None,
            "Compliance",
        )
    for pattern in _ADDRESS_PATTERNS:
        match = pattern.search(content.text)
        if match:
            return Finding(
                "Physical address",
                Status.PASS,
                f"Postal address found ({match.group(0).strip()}).",
                None,
                "Compliance",
            )
    return Finding(
        "Physical address",
        Status.WARN,
        "Could not find a physical mailing address.",
        "Add your postal address (street address or registered PO box) to the footer; "
        "CAN-SPAM requires one. If it is there in a format deliv does not recognize, ignore this.",
        "Compliance",
    )


def check_subject(content: EmailContent) -> Finding | None:
    """Check subject-line length and shouting (``.eml`` input only)."""
    if content.source_format != "eml":
        return None
    subject = (content.subject or "").strip()
    if not subject:
        return Finding(
            "Subject line",
            Status.FAIL,
            "The message has no subject line.",
            "Write a specific subject line; empty subjects are a strong spam signal.",
            "Content",
        )
    letters = [c for c in subject if c.isalpha()]
    caps = sum(c.isupper() for c in letters) / len(letters) if letters else 0
    if caps > 0.5 and len(letters) >= 8:
        return Finding(
            "Subject line",
            Status.WARN,
            f'Subject is mostly capitals: "{subject}".',
            "Use sentence case in subject lines.",
            "Content",
        )
    if len(subject) > SUBJECT_MAX_CHARS:
        return Finding(
            "Subject line",
            Status.WARN,
            f"Subject is {len(subject)} characters; most inboxes cut it off around 60-70.",
            "Front-load the point and trim to under 70 characters.",
            "Content",
        )
    return Finding(
        "Subject line", Status.PASS, f"Subject looks fine ({len(subject)} chars).", None, "Content"
    )


def check_content(content: EmailContent) -> dict[str, Any]:
    """Run every pre-send check on loaded content and return the verdict result dict."""
    spam_finding, spam = check_spam_score(content)
    findings: list[Finding] = [spam_finding]
    subject = check_subject(content)
    if subject:
        findings.append(subject)
    findings += [check_capitalization(content), check_punctuation(content)]
    findings.append(check_shorteners(content))
    findings += check_images(content)
    size = check_html_size(content)
    if size:
        findings.append(size)
    findings += [
        check_unsubscribe_link(content),
        check_list_unsubscribe(content),
        check_physical_address(content),
    ]

    verdict = VERDICTS[worst_status(findings)]
    order = {Status.FAIL: 0, Status.WARN: 1}
    blocking = sorted((f for f in findings if f.status in order), key=lambda f: order[f.status])
    reasons = [f"{f.check}: {f.message}" for f in blocking] or ["Every pre-send check passed."]
    counts = {s: sum(1 for f in findings if f.status is s) for s in (Status.FAIL, Status.WARN)}
    return envelope(
        "copy-check",
        content.source,
        input_format=content.source_format,
        verdict=verdict,
        exit_code=EXIT_CODES[verdict],
        summary=(
            f"{verdict}: {counts[Status.FAIL]} blocking issue(s), {counts[Status.WARN]} to review."
        ),
        reasons=reasons,
        spam_score=spam["score"],
        spam_grade=spam["grade"],
        rewrites=spam["rewrites"],
        findings=[f.to_dict() for f in findings],
    )


def check_file(path: str | Path) -> dict[str, Any]:
    """Load ``path`` (text, HTML, ``.eml``, or ``-`` for stdin) and run the pre-send gate."""
    return check_content(load_content(path))


_VERDICT_COLORS = {
    "PASS": typer.colors.GREEN,
    "REVIEW": typer.colors.YELLOW,
    "FAIL": typer.colors.RED,
}


def render(result: dict[str, Any]) -> str:
    """Render a copy-check result as a QA report."""
    verdict = result["verdict"]
    badge = typer.style(f" {verdict} ", fg=_VERDICT_COLORS[verdict], bold=True, reverse=True)
    lines = [
        heading(f"Pre-send QA report: {result['target']}"),
        f"Verdict: {badge}  (exit code {result['exit_code']})",
        f"Spam risk: {grade_badge(result['spam_grade'], result['spam_score'])}",
        "",
        subheading("Why" if verdict != "PASS" else "Summary"),
    ]
    lines += [f"  - {reason}" for reason in result["reasons"]]
    lines += ["", subheading("Checklist")]
    lines += render_findings(result["findings"], indent="  ")
    if result["rewrites"]:
        lines += ["", subheading("Copy fixes (highest-risk phrases first)")]
        for index, item in enumerate(result["rewrites"], start=1):
            where = "subject" if item["field"] == "subject" else f"line {item['line']}"
            lines.append(f'  {index}. "{item["found"]}" ({where}): {item["rewrite"]}')
    return "\n".join(lines)


def command(
    file: Annotated[
        str,
        typer.Argument(
            help="The email to check: a .html, .txt, or .eml file (use .eml to also check "
            "headers), or '-' for stdin."
        ),
    ],
    as_json: JsonFlag = False,
) -> None:
    """Pre-send QA gate: one PASS / REVIEW / FAIL verdict with the reasons behind it.

    Checks spam-trigger copy, link shorteners, shouting, punctuation, image-to-text balance, alt
    text, Gmail clipping, unsubscribe link and headers, and a physical mailing address.

    Exit codes for CI and ESP hooks: 0 = PASS, 1 = REVIEW, 2 = FAIL, 3 = input not readable.
    """
    if file != "-" and not Path(file).is_file():
        typer.echo(f"Error: file not found: {file}", err=True)
        raise typer.Exit(INPUT_ERROR_EXIT_CODE)
    result = check_file(file)
    emit(result, as_json, render)
    raise typer.Exit(result["exit_code"])
