"""Transport security checks: MTA-STS (record, policy file, MX coverage) and TLS-RPT."""

import fnmatch
from collections.abc import Sequence
from typing import Any

from deliv.checks import RETRY_HINT
from deliv.lib.dns import DNSClient, DNSLookupError, parse_tag_list
from deliv.lib.http import Fetcher, FetchError
from deliv.lib.scoring import Finding, Status


def parse_mta_sts_policy(text: str) -> tuple[dict[str, Any], list[str]]:
    """Parse an MTA-STS policy file into fields and a list of validation errors (RFC 8461)."""
    policy: dict[str, Any] = {"mx": []}
    errors: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        key, sep, value = line.partition(":")
        if not sep:
            errors.append(f"malformed line '{line}'")
            continue
        key, value = key.strip().lower(), value.strip()
        if key == "mx":
            policy["mx"].append(value.lower())
        else:
            policy[key] = value
    if policy.get("version") != "STSv1":
        errors.append("version must be STSv1")
    if policy.get("mode") not in {"enforce", "testing", "none"}:
        errors.append("mode must be enforce, testing, or none")
    max_age = policy.get("max_age", "")
    if not str(max_age).isdigit():
        errors.append("max_age must be a whole number of seconds")
    else:
        policy["max_age"] = int(max_age)
    if policy.get("mode") in {"enforce", "testing"} and not policy["mx"]:
        errors.append("at least one mx: line is required")
    return policy, errors


def _mx_matches(host: str, patterns: Sequence[str]) -> bool:
    host = host.lower().rstrip(".")
    for pattern in patterns:
        if pattern.startswith("*."):
            # A wildcard matches exactly one leftmost label (RFC 8461 section 4.1).
            suffix = pattern[1:]
            if host.endswith(suffix) and "." not in host[: -len(suffix)]:
                return True
        elif fnmatch.fnmatchcase(host, pattern):
            return True
    return False


def check_mta_sts(
    client: DNSClient, domain: str, fetcher: Fetcher, timeout: float
) -> list[Finding]:
    """Check the MTA-STS TXT record, fetch the policy file, and compare it to the domain's MX."""
    category = "MTA-STS"
    name = f"_mta-sts.{domain}"
    try:
        records = client.txt_with_prefix(name, "v=STSv1")
    except DNSLookupError as exc:
        return [
            Finding(
                "MTA-STS record",
                Status.WARN,
                f"Could not look up MTA-STS: {exc.reason}.",
                RETRY_HINT,
                category,
                weight=1,
            )
        ]
    if not records:
        return [
            Finding(
                "MTA-STS record",
                Status.WARN,
                "No MTA-STS record, so inbound mail to this domain can be downgraded to plaintext.",
                f"Publish 'v=STSv1; id=<timestamp>' at {name} and a policy file at "
                f"https://mta-sts.{domain}/.well-known/mta-sts.txt (start with mode: testing).",
                category,
                weight=1,
            )
        ]
    tags = parse_tag_list(records[0])
    if tags.get("id"):
        record_finding = Finding(
            "MTA-STS record",
            Status.PASS,
            f"MTA-STS record found (id={tags['id']}).",
            None,
            category,
            weight=1,
        )
    else:
        record_finding = Finding(
            "MTA-STS record",
            Status.WARN,
            "MTA-STS record is missing its id= tag.",
            "Add id=<unique value>; change it whenever the policy changes.",
            category,
            weight=1,
        )
    findings = [record_finding]

    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        text = fetcher(url, timeout)
    except FetchError as exc:
        findings.append(
            Finding(
                "MTA-STS policy",
                Status.WARN,
                f"Could not fetch the policy file: {exc}.",
                f"Serve the policy at {url} over HTTPS with a valid certificate and no redirects.",
                category,
                weight=1,
            )
        )
        return findings

    policy, errors = parse_mta_sts_policy(text)
    if errors:
        findings.append(
            Finding(
                "MTA-STS policy",
                Status.FAIL,
                f"Policy file is invalid: {'; '.join(errors)}.",
                "Fix the policy file; senders ignore an invalid MTA-STS policy.",
                category,
                weight=1,
                details={"url": url, "policy": policy},
            )
        )
        return findings

    mode = policy["mode"]
    try:
        mx_hosts = [host for _, host in client.mx(domain)]
    except DNSLookupError:
        mx_hosts = []
    unmatched = [host for host in mx_hosts if not _mx_matches(host, policy["mx"])]
    details = {"url": url, "policy": policy, "mx_hosts": mx_hosts, "unmatched_mx": unmatched}
    if unmatched and mode == "enforce":
        findings.append(
            Finding(
                "MTA-STS policy",
                Status.FAIL,
                f"Policy is in enforce mode but does not cover MX host(s): {', '.join(unmatched)}.",
                "Add matching mx: lines now; enforcing senders refuse to deliver to those hosts.",
                category,
                weight=1,
                details=details,
            )
        )
    elif mode == "enforce":
        findings.append(
            Finding(
                "MTA-STS policy",
                Status.PASS,
                f"Policy is in enforce mode (max_age {policy['max_age']}s) and covers every MX.",
                None,
                category,
                weight=1,
                details=details,
            )
        )
    else:
        findings.append(
            Finding(
                "MTA-STS policy",
                Status.WARN,
                f"Policy mode is '{mode}', so TLS is reported on but not enforced.",
                "Watch TLS-RPT reports for a few weeks, then switch to mode: enforce.",
                category,
                weight=1,
                details=details,
            )
        )
    return findings


def check_tls_rpt(client: DNSClient, domain: str) -> list[Finding]:
    """Check for an SMTP TLS reporting (TLS-RPT) record."""
    category = "TLS-RPT"
    name = f"_smtp._tls.{domain}"
    try:
        records = client.txt_with_prefix(name, "v=TLSRPTv1")
    except DNSLookupError as exc:
        return [
            Finding(
                "TLS-RPT",
                Status.WARN,
                f"Could not look up TLS-RPT: {exc.reason}.",
                RETRY_HINT,
                category,
                weight=0.5,
            )
        ]
    if not records:
        return [
            Finding(
                "TLS-RPT",
                Status.WARN,
                "No TLS-RPT record, so you will not hear about TLS delivery failures.",
                f"Publish 'v=TLSRPTv1; rua=mailto:tls-reports@{domain}' at {name}.",
                category,
                weight=0.5,
            )
        ]
    tags = parse_tag_list(records[0])
    if not tags.get("rua"):
        return [
            Finding(
                "TLS-RPT",
                Status.WARN,
                "TLS-RPT record has no rua= destination.",
                "Add rua=mailto:<address> or rua=https://<endpoint>.",
                category,
                weight=0.5,
            )
        ]
    return [
        Finding(
            "TLS-RPT", Status.PASS, f"TLS reports go to {tags['rua']}.", None, category, weight=0.5
        )
    ]
