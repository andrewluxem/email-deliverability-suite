"""``deliv header-analyze``: read a delivered message's headers and explain its authentication.

Parses every ``Authentication-Results`` header (one per reporting MTA), walks the ``Received``
chain to find the sending IP, and compares the From domain with the envelope-from (SPF) and DKIM
signing domains to decide whether DMARC alignment holds. Ends with a one-line diagnosis of the most
likely cause of any failure.
"""

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from typing import Annotated, Any

import typer

from deliv.lib.dns import organizational_domain, parse_tag_list
from deliv.lib.options import JsonFlag
from deliv.lib.output import emit, envelope, heading, render_findings, subheading, table
from deliv.lib.scoring import Finding, Status, grade, score_findings

_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)

_SPF_STATUS = {
    "pass": Status.PASS,
    "fail": Status.FAIL,
    "permerror": Status.FAIL,
    "softfail": Status.WARN,
    "neutral": Status.WARN,
    "none": Status.WARN,
    "temperror": Status.WARN,
}


@dataclass
class AuthResult:
    """One ``method=result`` entry from an Authentication-Results header."""

    method: str
    result: str
    properties: dict[str, str] = field(default_factory=dict)
    comment: str = ""


@dataclass
class AuthHeader:
    """One Authentication-Results header: who reported it and what they found."""

    reporter: str
    results: list[AuthResult]

    def first(self, method: str) -> AuthResult | None:
        """Return the first result for ``method`` (``spf``, ``dkim``, ``dmarc``...)."""
        return next((r for r in self.results if r.method == method), None)

    def all(self, method: str) -> list[AuthResult]:
        """Return every result for ``method`` (a message can carry several DKIM signatures)."""
        return [r for r in self.results if r.method == method]


@dataclass
class Hop:
    """One ``Received`` header, most recent first."""

    index: int
    from_host: str | None
    from_ip: str | None
    by_host: str | None
    date: str | None


def _split_outside_parens(value: str, sep: str = ";") -> list[str]:
    parts, depth, current = [], 0, []
    in_quotes = False
    for char in value:
        if char == '"' and depth == 0:
            in_quotes = not in_quotes
        elif char == "(" and not in_quotes:
            depth += 1
        elif char == ")" and not in_quotes and depth:
            depth -= 1
        if char == sep and depth == 0 and not in_quotes:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def _comments(text: str) -> tuple[str, str]:
    """Return ``(text_without_comments, joined_comment_text)``."""
    comments: list[str] = []
    out: list[str] = []
    depth, buffer = 0, []
    for char in text:
        if char == "(":
            depth += 1
            if depth == 1:
                buffer = []
                continue
        elif char == ")" and depth:
            depth -= 1
            if depth == 0:
                comments.append("".join(buffer).strip())
                continue
        if depth:
            buffer.append(char)
        else:
            out.append(char)
    return "".join(out), "; ".join(c for c in comments if c)


_RESULT_RE = re.compile(r"^\s*([a-z0-9_-]+)\s*=\s*([a-z0-9_-]+)", re.IGNORECASE)
_PROP_RE = re.compile(r'([a-z]+\.[a-z0-9_.-]+|reason)\s*=\s*("[^"]*"|[^\s;]+)', re.IGNORECASE)


def parse_authentication_results(value: str) -> AuthHeader:
    """Parse one Authentication-Results header value (RFC 8601)."""
    value = " ".join(value.split())
    segments = _split_outside_parens(value)
    reporter = _comments(segments[0])[0].strip().split(" ")[0] if segments else ""
    results: list[AuthResult] = []
    for segment in segments[1:]:
        text, comment = _comments(segment)
        match = _RESULT_RE.match(text)
        if not match or match.group(1).lower() == "none":
            continue
        properties = {
            key.lower(): val.strip('"') for key, val in _PROP_RE.findall(text[match.end() :])
        }
        results.append(
            AuthResult(match.group(1).lower(), match.group(2).lower(), properties, comment)
        )
    return AuthHeader(reporter, results)


_FROM_RE = re.compile(r"^\s*from\s+(\S+)", re.IGNORECASE)
_BY_RE = re.compile(r"\bby\s+(\S+)", re.IGNORECASE)
_IP_RE = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:.]+)\]|\b((?:\d{1,3}\.){3}\d{1,3})\b", re.IGNORECASE)


def parse_received(value: str, index: int) -> Hop:
    """Extract the from-host, from-IP, by-host, and timestamp from one Received header."""
    value = " ".join(value.split())
    body, _, date = value.rpartition(";") if ";" in value else (value, "", "")
    from_match = _FROM_RE.match(body)
    by_match = _BY_RE.search(body)
    from_clause = body[: by_match.start()] if by_match else body
    ip = None
    for match in _IP_RE.finditer(from_clause):
        candidate = match.group(1) or match.group(2)
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        ip = candidate
        break
    return Hop(
        index,
        from_match.group(1).strip("()[]") if from_match else None,
        ip,
        by_match.group(1) if by_match else None,
        date.strip() or None,
    )


def is_external_ip(value: str) -> bool:
    """True for addresses outside private, loopback, CGNAT, and link-local ranges."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not any(ip in network for network in _PRIVATE_NETWORKS if network.version == ip.version)


def _domain_of(value: str | None) -> str | None:
    if not value:
        return None
    address = parseaddr(value)[1] or value
    domain = address.rsplit("@", 1)[-1].strip().strip("<>").lower().rstrip(".")
    return domain or None


def _aligned(domain: str | None, from_domain: str | None) -> bool:
    if not domain or not from_domain:
        return False
    return organizational_domain(domain) == organizational_domain(from_domain)


def analyze_message(raw: bytes, source: str = "-") -> dict[str, Any]:
    """Analyze raw RFC 5322 message bytes and return the header-analyze result dict."""
    message = BytesParser(policy=policy.compat32).parsebytes(raw, headersonly=True)
    auth_headers = [
        parse_authentication_results(str(v)) for v in message.get_all("Authentication-Results", [])
    ]
    hops = [parse_received(str(v), i) for i, v in enumerate(message.get_all("Received", []), 1)]
    sending = next((h for h in hops if h.from_ip and is_external_ip(h.from_ip)), None)

    from_domain = _domain_of(message.get("From"))
    primary = auth_headers[0] if auth_headers else None
    spf = primary.first("spf") if primary else None
    dmarc = primary.first("dmarc") if primary else None
    dkim_results = primary.all("dkim") if primary else []

    envelope_from = None
    if spf:
        envelope_from = _domain_of(spf.properties.get("smtp.mailfrom"))
    envelope_from = envelope_from or _domain_of(message.get("Return-Path"))

    signatures = [parse_tag_list(str(v)) for v in message.get_all("DKIM-Signature", [])]
    dkim_domains: list[dict[str, Any]] = []
    for result in dkim_results:
        domain = result.properties.get("header.d") or _domain_of(result.properties.get("header.i"))
        dkim_domains.append({"domain": domain, "result": result.result})
    if not dkim_domains:
        dkim_domains = [
            {"domain": s.get("d", "").lower(), "result": "unverified"} for s in signatures
        ]

    spf_pass = bool(spf and spf.result == "pass")
    spf_aligned = _aligned(envelope_from, from_domain)
    dkim_aligned_pass = any(
        d["result"] == "pass" and _aligned(d["domain"], from_domain) for d in dkim_domains
    )
    dmarc_would_pass = (spf_pass and spf_aligned) or dkim_aligned_pass

    alignment = {
        "from_domain": from_domain,
        "envelope_from_domain": envelope_from,
        "dkim_domains": dkim_domains,
        "spf_aligned": spf_aligned,
        "dkim_aligned": any(_aligned(d["domain"], from_domain) for d in dkim_domains),
        "dmarc_would_pass": dmarc_would_pass,
        "verdict": "aligned" if dmarc_would_pass else "not aligned",
    }
    findings = _findings(primary, spf, dkim_results, dmarc, alignment)
    diagnosis = diagnose(primary, spf, dkim_results, dmarc, alignment, sending)
    score = score_findings(findings)
    return envelope(
        "header-analyze",
        source,
        subject=message.get("Subject"),
        score=score,
        grade=grade(score),
        verdict="PASS" if dmarc_would_pass and (not dmarc or dmarc.result == "pass") else "FAIL",
        summary=diagnosis,
        diagnosis=diagnosis,
        sending_ip=sending.from_ip if sending else None,
        sending_host=sending.from_host if sending else None,
        auth_results=[
            {"reporter": h.reporter, "results": [asdict(r) for r in h.results]}
            for h in auth_headers
        ],
        received_chain=[asdict(h) for h in hops],
        alignment=alignment,
        findings=[f.to_dict() for f in findings],
    )


def _findings(
    primary: AuthHeader | None,
    spf: AuthResult | None,
    dkim_results: list[AuthResult],
    dmarc: AuthResult | None,
    alignment: dict[str, Any],
) -> list[Finding]:
    if primary is None:
        return [
            Finding(
                "Authentication-Results",
                Status.WARN,
                "No Authentication-Results header: this copy was never checked by a receiving "
                "server.",
                "Analyze a copy saved from a recipient inbox ('Show original' / 'View source').",
                "Auth",
            )
        ]
    findings: list[Finding] = []
    if spf:
        findings.append(
            Finding(
                "SPF",
                _SPF_STATUS.get(spf.result, Status.WARN),
                f"spf={spf.result} for {spf.properties.get('smtp.mailfrom', 'unknown sender')}"
                + (f" ({spf.comment})" if spf.comment else ""),
                None
                if spf.result == "pass"
                else "Add the sending service to the envelope "
                "domain's SPF record (or use the ESP's custom return-path setup).",
                "Auth",
            )
        )
    else:
        findings.append(
            Finding("SPF", Status.WARN, "No SPF result reported.", None, "Auth", weight=0.5)
        )

    passing = [r for r in dkim_results if r.result == "pass"]
    if passing:
        domains = ", ".join(r.properties.get("header.d", "?") for r in passing)
        findings.append(Finding("DKIM", Status.PASS, f"dkim=pass (d={domains}).", None, "Auth"))
    elif dkim_results:
        first = dkim_results[0]
        findings.append(
            Finding(
                "DKIM",
                Status.FAIL,
                f"dkim={first.result} (d={first.properties.get('header.d', '?')})"
                + (f" ({first.comment})" if first.comment else ""),
                "Check the DKIM key in DNS matches the signing key, and that nothing rewrites the "
                "message after signing (footers, link rewriting, forwarding).",
                "Auth",
            )
        )
    else:
        findings.append(
            Finding(
                "DKIM",
                Status.FAIL,
                "No DKIM signature was verified.",
                "Turn on DKIM signing with your own domain in your ESP.",
                "Auth",
            )
        )

    if dmarc:
        status = Status.PASS if dmarc.result == "pass" else Status.FAIL
        if dmarc.result in {"none", "temperror"}:
            status = Status.WARN
        findings.append(
            Finding(
                "DMARC",
                status,
                f"dmarc={dmarc.result} for header.from="
                f"{dmarc.properties.get('header.from', alignment['from_domain'])}"
                + (f" ({dmarc.comment})" if dmarc.comment else ""),
                None
                if status is Status.PASS
                else "Get SPF or DKIM to both pass and align with the "
                "From domain (see the alignment check).",
                "Auth",
            )
        )
    else:
        findings.append(
            Finding(
                "DMARC",
                Status.WARN,
                "No DMARC result reported (the From domain may have no DMARC record).",
                f"Publish a DMARC record for {alignment['from_domain']}.",
                "Auth",
            )
        )

    if alignment["dmarc_would_pass"]:
        via = []
        if alignment["spf_aligned"]:
            via.append("SPF")
        if (
            any(d["result"] == "pass" for d in alignment["dkim_domains"])
            and alignment["dkim_aligned"]
        ):
            via.append("DKIM")
        findings.append(
            Finding(
                "Alignment",
                Status.PASS,
                f"From domain {alignment['from_domain']} aligns via {' and '.join(via)}.",
                None,
                "Alignment",
            )
        )
    else:
        spf_domain = alignment["envelope_from_domain"]
        dkim_names = ", ".join(d["domain"] or "?" for d in alignment["dkim_domains"]) or "none"
        if alignment["spf_aligned"] or alignment["dkim_aligned"]:
            message = (
                f"The aligned mechanisms did not pass: SPF domain {spf_domain} and DKIM "
                f"domain(s) {dkim_names} line up with {alignment['from_domain']}, but the ones "
                "that line up failed verification."
            )
            fix = "Fix the failing SPF/DKIM result shown above; alignment itself is fine."
        else:
            message = (
                f"Neither the SPF domain ({spf_domain}) nor the DKIM domain(s) ({dkim_names}) "
                f"match the From domain ({alignment['from_domain']})."
            )
            fix = (
                "Set up custom DKIM for your From domain in your ESP (d=your domain); optionally "
                "a custom return-path on a subdomain so SPF aligns too."
            )
        findings.append(Finding("Alignment", Status.FAIL, message, fix, "Alignment"))
    return findings


def diagnose(
    primary: AuthHeader | None,
    spf: AuthResult | None,
    dkim_results: list[AuthResult],
    dmarc: AuthResult | None,
    alignment: dict[str, Any],
    sending: Hop | None,
) -> str:
    """Return a one-line explanation of the most likely cause of any authentication failure."""
    from_domain = alignment["from_domain"]
    ip = sending.from_ip if sending else "the sending server"
    if primary is None:
        return (
            "No receiving server has checked this copy (no Authentication-Results header), so "
            "there is nothing to diagnose. Save the message from a recipient inbox and rerun."
        )
    dkim_pass = [r for r in dkim_results if r.result == "pass"]
    dkim_fail = [r for r in dkim_results if r.result in {"fail", "neutral", "permerror"}]
    if alignment["dmarc_would_pass"] and (not dmarc or dmarc.result == "pass"):
        if spf and spf.result != "pass":
            return (
                f"Healthy: DMARC passes on aligned DKIM. SPF shows {spf.result} for {ip}, which "
                "is typical of forwarding and does not affect delivery here."
            )
        return "Healthy: SPF, DKIM, and DMARC pass and align with the From domain."
    if dkim_fail and any("body hash" in r.comment.lower() for r in dkim_fail):
        return (
            "The DKIM body hash did not verify: the message was changed after it was signed "
            "(a forwarder, mailing list, security gateway, or footer injection). With SPF also "
            f"failing for {ip}, DMARC fails."
        )
    if (
        dkim_pass
        and not alignment["dkim_aligned"]
        and spf
        and spf.result == "pass"
        and not (alignment["spf_aligned"])
    ):
        signer = dkim_pass[0].properties.get("header.d", "another domain")
        return (
            f"Your ESP is authenticating as itself: DKIM is signed by {signer} and the "
            f"return-path is {alignment['envelope_from_domain']}, neither of which is "
            f"{from_domain}. Set up custom DKIM for {from_domain}."
        )
    if spf and spf.result in {"fail", "softfail"} and not dkim_pass:
        return (
            f"{ip} is not listed in the SPF record for {alignment['envelope_from_domain']} and "
            "there is no passing DKIM signature. If this is your ESP, add its include to SPF "
            "and enable DKIM signing; if not, someone is spoofing you."
        )
    if not dkim_results and spf and spf.result == "pass" and not alignment["spf_aligned"]:
        return (
            f"SPF passes for {alignment['envelope_from_domain']} but it does not match "
            f"{from_domain}, and the message has no DKIM signature. Enable DKIM signing with "
            f"d={from_domain}."
        )
    if dkim_fail:
        return (
            "DKIM verification failed. The published key may not match the signing key (check "
            "the selector's DNS record), or the message was modified in transit."
        )
    return (
        f"DMARC did not pass for {from_domain}: no passing SPF or DKIM result aligns with it. "
        "Check the findings above for the failing mechanism."
    )


def analyze_file(path: str | Path) -> dict[str, Any]:
    """Analyze an ``.eml`` file on disk."""
    return analyze_message(Path(path).read_bytes(), str(path))


def render(result: dict[str, Any]) -> str:
    """Render a header-analyze result for the terminal."""
    lines = [heading(f"Header analysis: {result['target']}")]
    if result.get("subject"):
        lines.append(f"Subject: {result['subject']}")
    lines += ["", subheading("Authentication results (per reporting server)")]
    if result["auth_results"]:
        rows = []
        for header in result["auth_results"]:
            by_method: dict[str, list[str]] = {}
            for item in header["results"]:
                by_method.setdefault(item["method"], []).append(item["result"])
            rows.append(
                [header["reporter"] or "(unnamed)"]
                + ["/".join(by_method.get(m, ["-"])) for m in ("spf", "dkim", "dmarc")]
            )
        lines.append(table(["Reported by", "SPF", "DKIM", "DMARC"], rows))
    else:
        lines.append("  (none)")

    lines += ["", subheading("Received chain (most recent first)")]
    if result["received_chain"]:
        lines.append(
            table(
                ["Hop", "From host", "IP", "By"],
                [
                    [h["index"], h["from_host"] or "-", h["from_ip"] or "-", h["by_host"] or "-"]
                    for h in result["received_chain"]
                ],
            )
        )
    sender = result["sending_ip"] or "unknown"
    lines.append(
        f"Sending IP: {sender}" + (f" ({result['sending_host']})" if result["sending_host"] else "")
    )

    alignment = result["alignment"]
    dkim = ", ".join(f"{d['domain']} ({d['result']})" for d in alignment["dkim_domains"]) or "none"
    lines += [
        "",
        subheading("Alignment"),
        f"  From domain:      {alignment['from_domain']}",
        f"  Envelope-from:    {alignment['envelope_from_domain'] or 'unknown'}"
        f"  ({'aligned' if alignment['spf_aligned'] else 'not aligned'})",
        f"  DKIM signers:     {dkim}"
        f"  ({'aligned' if alignment['dkim_aligned'] else 'not aligned'})",
        f"  Verdict:          {alignment['verdict'].upper()}",
        "",
        subheading("Checks"),
        *render_findings(result["findings"], indent="  "),
        "",
        subheading("Diagnosis"),
        f"  {result['diagnosis']}",
    ]
    return "\n".join(lines)


def command(
    file: Annotated[
        Path,
        typer.Argument(
            help="A saved message (.eml). In Gmail use 'Show original' > 'Download original'.",
            exists=True,
            dir_okay=False,
        ),
    ],
    as_json: JsonFlag = False,
) -> None:
    """Explain a delivered message's SPF, DKIM, DMARC, and alignment from its headers.

    Shows what each receiving server reported, which IP sent the message, whether the From domain
    lines up with the SPF and DKIM domains, and the most likely cause of any failure.
    """
    emit(analyze_file(file), as_json, render)
