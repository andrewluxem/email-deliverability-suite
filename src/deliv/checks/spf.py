"""SPF checks: record presence and syntax, the 10-lookup limit, and the ``all`` policy."""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from deliv.checks import RETRY_HINT
from deliv.lib.dns import DNSClient, DNSLookupError, normalize_domain
from deliv.lib.scoring import Finding, Status

SPF_LOOKUP_LIMIT = 10
SPF_MECHANISMS = frozenset({"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"})
SPF_LOOKUP_TERMS = frozenset({"include", "a", "mx", "ptr", "exists", "redirect"})
SPF_QUALIFIERS = "+-~?"
MAX_SPF_DEPTH = 10


@dataclass
class SpfTerm:
    """One parsed SPF term: a mechanism (``~all``, ``include:x``) or a modifier (``redirect=x``)."""

    kind: str  # "mechanism" or "modifier"
    name: str
    value: str
    qualifier: str = "+"


def parse_spf(record: str) -> tuple[list[SpfTerm], list[str]]:
    """Parse an SPF record into terms and a list of syntax errors."""
    terms: list[SpfTerm] = []
    errors: list[str] = []
    parts = record.split()
    if not parts or parts[0].lower() != "v=spf1":
        return terms, ["record does not start with v=spf1"]
    for raw in parts[1:]:
        if "=" in raw and ":" not in raw.split("=", 1)[0]:
            name, _, value = raw.partition("=")
            name = name.lower()
            if name not in {"redirect", "exp"} and not name.replace("-", "").isalnum():
                errors.append(f"invalid modifier '{raw}'")
                continue
            if not value:
                errors.append(f"modifier '{name}' has no value")
            terms.append(SpfTerm("modifier", name, value))
            continue
        qualifier = "+"
        body = raw
        if body[0] in SPF_QUALIFIERS:
            qualifier, body = body[0], body[1:]
        name, _, value = body.partition(":")
        if "/" in name and name.split("/", 1)[0].lower() in {"a", "mx"}:
            name, value = name.split("/", 1)[0], ""
        name = name.lower()
        if name not in SPF_MECHANISMS:
            errors.append(f"unknown mechanism '{raw}'")
            continue
        if name in {"include", "exists", "ip4", "ip6"} and not value:
            errors.append(f"'{name}' requires a value")
        terms.append(SpfTerm("mechanism", name, value, qualifier))
    return terms, errors


def _spf_record_for(client: DNSClient, domain: str) -> list[str]:
    return client.txt_with_prefix(domain, "v=spf1")


def count_spf_lookups(
    client: DNSClient,
    domain: str,
    record: str,
    _seen: set[str] | None = None,
    _depth: int = 0,
) -> tuple[int, list[str]]:
    """Count DNS-querying SPF terms, following ``include`` and ``redirect`` recursively.

    Returns the lookup count and a list of problems found along the way (missing included
    records, loops, lookup failures).
    """
    seen = _seen if _seen is not None else {domain}
    problems: list[str] = []
    if _depth > MAX_SPF_DEPTH:
        return 0, [f"includes nest deeper than {MAX_SPF_DEPTH} levels"]
    terms, _ = parse_spf(record)
    count = 0
    for term in terms:
        if term.name not in SPF_LOOKUP_TERMS:
            continue
        count += 1
        if term.name not in {"include", "redirect"} or not term.value:
            continue
        target = normalize_domain(term.value)
        if "%" in target:
            continue  # macro: expanded at send time, cannot be followed statically
        if target in seen:
            problems.append(f"loop detected at {term.name}:{target}")
            continue
        seen.add(target)
        try:
            nested = _spf_record_for(client, target)
        except DNSLookupError as exc:
            problems.append(f"could not resolve {term.name}:{target} ({exc.reason})")
            continue
        if not nested:
            problems.append(f"{term.name}:{target} has no SPF record (receivers return permerror)")
            continue
        nested_count, nested_problems = count_spf_lookups(
            client, target, nested[0], seen, _depth + 1
        )
        count += nested_count
        problems.extend(nested_problems)
    return count, problems


def check_spf(client: DNSClient, domain: str) -> tuple[list[Finding], str | None]:
    """Run the SPF checks and return findings plus the raw record (if exactly one exists)."""
    category = "SPF"
    try:
        records = _spf_record_for(client, domain)
    except DNSLookupError as exc:
        return [
            Finding(
                "SPF record",
                Status.WARN,
                f"Could not look up SPF: {exc.reason}.",
                RETRY_HINT,
                category,
                weight=3,
            )
        ], None
    if not records:
        return [
            Finding(
                "SPF record",
                Status.FAIL,
                "No SPF record found, so receivers cannot tell which servers may send as you.",
                "Publish a TXT record like 'v=spf1 include:<your ESP> -all' at the domain root.",
                category,
                weight=3,
                critical=True,
            )
        ], None
    if len(records) > 1:
        return [
            Finding(
                "SPF record",
                Status.FAIL,
                f"{len(records)} SPF records found. More than one is a permanent error.",
                "Merge every sender into a single v=spf1 TXT record and delete the others.",
                category,
                weight=3,
                critical=True,
                details={"records": records},
            )
        ], None

    record = records[0]
    findings: list[Finding] = []
    terms, errors = parse_spf(record)
    if errors:
        findings.append(
            Finding(
                "SPF record",
                Status.FAIL,
                f"SPF record has syntax errors: {'; '.join(errors)}.",
                "Fix the listed terms; receivers treat a malformed SPF record as permerror.",
                category,
                weight=3,
                critical=True,
                details={"record": record},
            )
        )
    elif any(t.name == "ptr" for t in terms):
        findings.append(
            Finding(
                "SPF record",
                Status.WARN,
                "SPF record uses the deprecated 'ptr' mechanism.",
                "Replace 'ptr' with explicit ip4/ip6 or include terms (RFC 7208 section 5.5).",
                category,
                weight=3,
                details={"record": record},
            )
        )
    else:
        findings.append(
            Finding(
                "SPF record",
                Status.PASS,
                f"Valid SPF record: {record}",
                None,
                category,
                weight=3,
                details={"record": record},
            )
        )

    lookups, problems = count_spf_lookups(client, domain, record)
    details: dict[str, Any] = {"lookups": lookups, "limit": SPF_LOOKUP_LIMIT, "problems": problems}
    if lookups > SPF_LOOKUP_LIMIT:
        findings.append(
            Finding(
                "SPF lookups",
                Status.FAIL,
                f"SPF needs {lookups} DNS lookups; the limit is {SPF_LOOKUP_LIMIT}, so SPF "
                "returns permerror.",
                "Remove unused includes, replace includes with ip4/ip6 ranges, or split sending "
                "across subdomains.",
                category,
                weight=2,
                details=details,
            )
        )
    elif problems:
        findings.append(
            Finding(
                "SPF lookups",
                Status.WARN,
                f"SPF uses {lookups} of {SPF_LOOKUP_LIMIT} lookups, but: {'; '.join(problems)}.",
                "Fix or remove the broken include/redirect targets listed above.",
                category,
                weight=2,
                details=details,
            )
        )
    elif lookups >= SPF_LOOKUP_LIMIT - 1:
        findings.append(
            Finding(
                "SPF lookups",
                Status.WARN,
                f"SPF uses {lookups} of {SPF_LOOKUP_LIMIT} DNS lookups. One more sender breaks it.",
                "Flatten or remove includes before adding another sending service.",
                category,
                weight=2,
                details=details,
            )
        )
    else:
        findings.append(
            Finding(
                "SPF lookups",
                Status.PASS,
                f"SPF uses {lookups} of {SPF_LOOKUP_LIMIT} allowed DNS lookups.",
                None,
                category,
                weight=2,
                details=details,
            )
        )

    findings.append(_spf_policy_finding(terms))
    return findings, record


def _spf_policy_finding(terms: Sequence[SpfTerm]) -> Finding:
    category = "SPF"
    all_term = next((t for t in terms if t.name == "all"), None)
    has_redirect = any(t.kind == "modifier" and t.name == "redirect" for t in terms)
    if all_term is None:
        if has_redirect:
            return Finding(
                "SPF policy",
                Status.PASS,
                "SPF delegates its policy with redirect=.",
                None,
                category,
                weight=3,
            )
        return Finding(
            "SPF policy",
            Status.WARN,
            "SPF has no 'all' term, so unlisted senders get a neutral result.",
            "End the record with '-all' (hard fail) or '~all' (soft fail).",
            category,
            weight=3,
        )
    qualifier = all_term.qualifier
    if qualifier == "-":
        return Finding(
            "SPF policy",
            Status.PASS,
            "SPF ends in -all: unlisted senders hard fail.",
            None,
            category,
            weight=3,
        )
    if qualifier == "~":
        return Finding(
            "SPF policy",
            Status.PASS,
            "SPF ends in ~all: unlisted senders soft fail (DMARC does the enforcing).",
            None,
            category,
            weight=3,
        )
    if qualifier == "?":
        return Finding(
            "SPF policy",
            Status.WARN,
            "SPF ends in ?all, which tells receivers nothing about unlisted senders.",
            "Change '?all' to '~all' or '-all'.",
            category,
            weight=3,
        )
    return Finding(
        "SPF policy",
        Status.FAIL,
        "SPF ends in +all, which authorizes every server on the internet to send as you.",
        "Replace '+all' with '-all' or '~all' immediately.",
        category,
        weight=3,
        critical=True,
    )
