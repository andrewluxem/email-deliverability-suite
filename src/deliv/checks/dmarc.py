"""DMARC checks: record validity, policy strength, pct, reporting, subdomains, alignment."""

from deliv.checks import RETRY_HINT
from deliv.lib.dns import DNSClient, DNSLookupError, parse_tag_list
from deliv.lib.scoring import Finding, Status

_DMARC_POLICIES = {"none", "quarantine", "reject"}
_POLICY_PAST = {"quarantine": "quarantined", "reject": "rejected"}


def check_dmarc(client: DNSClient, domain: str) -> tuple[list[Finding], dict[str, str] | None]:
    """Run the DMARC checks and return findings plus the parsed tags (when valid)."""
    category = "DMARC"
    name = f"_dmarc.{domain}"
    try:
        records = client.txt_with_prefix(name, "v=DMARC1")
    except DNSLookupError as exc:
        return [
            Finding(
                "DMARC record",
                Status.WARN,
                f"Could not look up DMARC: {exc.reason}.",
                RETRY_HINT,
                category,
                weight=3,
            )
        ], None
    if not records:
        return [
            Finding(
                "DMARC record",
                Status.FAIL,
                "No DMARC record. Gmail and Yahoo require one for bulk senders.",
                f"Publish 'v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain}' at {name}, then "
                "tighten to quarantine or reject once reports look clean.",
                category,
                weight=3,
                critical=True,
            )
        ], None
    if len(records) > 1:
        return [
            Finding(
                "DMARC record",
                Status.FAIL,
                f"{len(records)} DMARC records found; receivers ignore DMARC when several exist.",
                f"Keep exactly one v=DMARC1 TXT record at {name}.",
                category,
                weight=3,
                critical=True,
                details={"records": records},
            )
        ], None

    record = records[0]
    tags = parse_tag_list(record)
    policy = tags.get("p", "").lower()
    if policy not in _DMARC_POLICIES:
        return [
            Finding(
                "DMARC record",
                Status.FAIL,
                "DMARC record is missing a valid p= policy tag.",
                "Add p=none, p=quarantine, or p=reject.",
                category,
                weight=3,
                critical=True,
                details={"record": record},
            )
        ], None

    findings = [
        Finding(
            "DMARC record",
            Status.PASS,
            f"Valid DMARC record: {record}",
            None,
            category,
            weight=3,
            details={"record": record, "tags": tags},
        )
    ]
    if policy == "none":
        findings.append(
            Finding(
                "DMARC policy",
                Status.WARN,
                "Policy is p=none: you get reports, but spoofed mail is still delivered.",
                "Review rua reports, fix any legitimate senders that fail, then move to "
                "p=quarantine and later p=reject.",
                category,
                weight=5,
            )
        )
    else:
        handled = _POLICY_PAST[policy]
        findings.append(
            Finding(
                "DMARC policy",
                Status.PASS,
                f"Policy is p={policy}: failing mail is {handled}, which blocks spoofing.",
                None,
                category,
                weight=5,
            )
        )

    findings.append(_dmarc_pct_finding(tags.get("pct"), policy))
    findings.append(_dmarc_reporting_finding(tags, domain))
    findings.append(_dmarc_subdomain_finding(tags.get("sp", "").lower(), policy))
    adkim = "strict" if tags.get("adkim", "r").lower() == "s" else "relaxed"
    aspf = "strict" if tags.get("aspf", "r").lower() == "s" else "relaxed"
    findings.append(
        Finding(
            "DMARC alignment",
            Status.INFO,
            f"DKIM alignment is {adkim}, SPF alignment is {aspf}.",
            "Relaxed alignment is right for most senders; strict breaks mail sent from subdomains."
            if "strict" in (adkim, aspf)
            else None,
            category,
            weight=0,
            details={"adkim": adkim, "aspf": aspf},
        )
    )
    return findings, tags


def _dmarc_pct_finding(pct_value: str | None, policy: str) -> Finding:
    category = "DMARC"
    if pct_value is None:
        return Finding(
            "DMARC pct",
            Status.PASS,
            "Policy applies to 100% of failing mail.",
            None,
            category,
            weight=1,
        )
    try:
        pct = int(pct_value)
    except ValueError:
        return Finding(
            "DMARC pct",
            Status.WARN,
            f"pct={pct_value} is not a number.",
            "Set pct to an integer 0-100, or remove it.",
            category,
            weight=1,
        )
    if not 0 <= pct <= 100:
        return Finding(
            "DMARC pct",
            Status.WARN,
            f"pct={pct} is outside 0-100.",
            "Set pct to an integer 0-100, or remove it.",
            category,
            weight=1,
        )
    if pct < 100 and policy != "none":
        return Finding(
            "DMARC pct",
            Status.WARN,
            f"pct={pct}: only {pct}% of failing mail gets p={policy}; the rest is treated "
            "one step softer.",
            "Raise pct to 100 once reports show legitimate mail passing.",
            category,
            weight=1,
        )
    return Finding("DMARC pct", Status.PASS, f"pct={pct}.", None, category, weight=1)


def _dmarc_reporting_finding(tags: dict[str, str], domain: str) -> Finding:
    category = "DMARC"
    rua = tags.get("rua")
    ruf = tags.get("ruf")
    details = {"rua": rua, "ruf": ruf}
    if not rua:
        return Finding(
            "DMARC reporting",
            Status.WARN,
            "No rua= address, so you receive no aggregate reports and fly blind.",
            f"Add rua=mailto:dmarc-reports@{domain} (or your DMARC vendor's address).",
            category,
            weight=1.5,
            details=details,
        )
    forensic = (
        f"; failure reports to {ruf}" if ruf else "; no ruf= (few receivers send them anyway)"
    )
    return Finding(
        "DMARC reporting",
        Status.PASS,
        f"Aggregate reports go to {rua}{forensic}.",
        None,
        category,
        weight=1.5,
        details=details,
    )


def _dmarc_subdomain_finding(subdomain_policy: str, policy: str) -> Finding:
    category = "DMARC"
    if not subdomain_policy:
        return Finding(
            "DMARC subdomains",
            Status.PASS,
            f"Subdomains inherit p={policy} (no sp= tag).",
            None,
            category,
            weight=1,
        )
    if subdomain_policy not in _DMARC_POLICIES:
        return Finding(
            "DMARC subdomains",
            Status.WARN,
            f"sp={subdomain_policy} is not valid.",
            "Use sp=none, sp=quarantine, or sp=reject.",
            category,
            weight=1,
        )
    if subdomain_policy == "none" and policy != "none":
        return Finding(
            "DMARC subdomains",
            Status.WARN,
            f"sp=none leaves every subdomain spoofable even though p={policy}.",
            "Remove sp= so subdomains inherit the main policy, or set sp=quarantine.",
            category,
            weight=1,
        )
    return Finding(
        "DMARC subdomains",
        Status.PASS,
        f"Subdomain policy is sp={subdomain_policy}.",
        None,
        category,
        weight=1,
    )
