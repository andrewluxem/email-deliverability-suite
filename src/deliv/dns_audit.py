"""``deliv dns-audit``: grade the DNS records that decide whether mail reaches the inbox.

Checks SPF, DKIM, DMARC, BIMI, MTA-STS, and TLS-RPT for one domain, explains every result in one
plain-English line, attaches a remediation hint to everything that is not a pass, and rolls it all
up into a 0-100 score and an A-F grade.
"""

from collections.abc import Sequence
from typing import Annotated, Any

import typer

from deliv.checks.bimi import check_bimi
from deliv.checks.dkim import DEFAULT_DKIM_SELECTORS, check_dkim
from deliv.checks.dmarc import check_dmarc
from deliv.checks.spf import check_spf
from deliv.checks.transport import check_mta_sts, check_tls_rpt
from deliv.lib.dns import DNSClient, normalize_domain
from deliv.lib.http import Fetcher, fetch_text
from deliv.lib.options import DEFAULT_TIMEOUT, JsonFlag, NameserverOption, TimeoutOption
from deliv.lib.output import emit, envelope, grade_badge, heading, render_findings, subheading
from deliv.lib.scoring import Finding, count_by_status, grade, score_findings


def audit_domain(
    domain: str,
    client: DNSClient | None = None,
    fetcher: Fetcher | None = None,
    selectors: Sequence[str] = (),
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Run every DNS authentication check for ``domain`` and return the graded result dict.

    Args:
        domain: The sending domain to audit.
        client: DNS client to use (defaults to the system resolver with ``timeout``).
        fetcher: HTTPS fetcher for the MTA-STS policy (defaults to :func:`fetch_text`).
        selectors: Extra DKIM selectors to probe in addition to the common defaults.
        timeout: Per-lookup timeout in seconds.

    Returns:
        A result dict (see :func:`deliv.lib.output.envelope`) with score, grade, and findings.
    """
    domain = normalize_domain(domain)
    client = client or DNSClient(timeout=timeout)
    fetcher = fetcher or fetch_text
    probe = list(dict.fromkeys([*selectors, *DEFAULT_DKIM_SELECTORS]))

    findings: list[Finding] = []
    spf_findings, spf_record = check_spf(client, domain)
    findings += spf_findings
    findings += check_dkim(client, domain, probe)
    dmarc_findings, dmarc_tags = check_dmarc(client, domain)
    findings += dmarc_findings
    dmarc_policy = (dmarc_tags or {}).get("p", "").lower() or None
    findings += check_bimi(client, domain, dmarc_policy)
    findings += check_mta_sts(client, domain, fetcher, timeout)
    findings += check_tls_rpt(client, domain)

    score = score_findings(findings)
    counts = count_by_status(findings)
    return envelope(
        "dns-audit",
        domain,
        score=score,
        grade=grade(score),
        summary=(
            f"{counts['pass']} passed, {counts['warn']} warnings, {counts['fail']} failed "
            f"across SPF, DKIM, DMARC, BIMI, MTA-STS, and TLS-RPT."
        ),
        counts=counts,
        records={"spf": spf_record, "dmarc": dmarc_tags},
        findings=[f.to_dict() for f in findings],
    )


def render(result: dict[str, Any]) -> str:
    """Render a dns-audit result for the terminal."""
    lines = [
        heading(f"DNS authentication audit: {result['target']}"),
        f"{grade_badge(result['grade'], result['score'])}   {result['summary']}",
        "",
    ]
    categories: dict[str, list[dict[str, Any]]] = {}
    for finding in result["findings"]:
        categories.setdefault(finding["category"], []).append(finding)
    for category, items in categories.items():
        lines.append(subheading(category))
        lines.extend(render_findings(items, indent="  "))
        lines.append("")
    return "\n".join(lines).rstrip()


def command(
    domain: Annotated[str, typer.Argument(help="The sending domain to audit, e.g. example.com.")],
    selector: Annotated[
        list[str] | None,
        typer.Option(
            "--selector",
            "-s",
            help="A DKIM selector your ESP gave you. Repeat for several. Common ones are always "
            "probed.",
        ),
    ] = None,
    timeout: TimeoutOption = DEFAULT_TIMEOUT,
    nameserver: NameserverOption = None,
    as_json: JsonFlag = False,
) -> None:
    """Grade a domain's email authentication DNS: SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT.

    Every check gets PASS, WARN, or FAIL with a plain-English reason and a fix. The domain gets an
    overall A-F grade.
    """
    client = DNSClient(timeout=timeout, nameservers=nameserver)
    result = audit_domain(domain, client=client, selectors=selector or (), timeout=timeout)
    emit(result, as_json, render)
