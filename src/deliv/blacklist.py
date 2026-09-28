"""``deliv blacklist``: check an IP or domain against the DNS blocklists that matter for email.

IP addresses are checked against IP blocklists (Spamhaus ZEN, Barracuda, SpamCop, PSBL, Mailspike,
UCEPROTECT); domains against domain blocklists (Spamhaus DBL, SURBL, URIBL). Every list is queried
over plain DNS, in parallel, with a per-query timeout. Timeouts, refusals, and rate-limit answers
become warnings, never crashes.

By default each list is also asked about its own published test entry. A list that does not report
its test entry as listed is marked *unverified*: its "not listed" answer cannot be trusted. This
catches the most common false all-clear, Spamhaus silently refusing queries from public resolvers.
"""

from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import Annotated, Any

import typer

from deliv.lib.dns import DNSClient, DNSLookupError, is_ip_address, normalize_domain, reverse_ip
from deliv.lib.options import DEFAULT_TIMEOUT, JsonFlag, NameserverOption, TimeoutOption
from deliv.lib.output import emit, envelope, grade_badge, heading, subheading, table
from deliv.lib.scoring import Finding, Status, grade, score_findings

LISTED, CLEAN, ERROR, UNVERIFIED, SKIPPED = "listed", "clean", "error", "unverified", "skipped"

_SPAMHAUS_ERRORS = {
    "127.255.255.252": "query refused: malformed query name",
    "127.255.255.254": "query refused: public or open resolver (use your own resolver)",
    "127.255.255.255": "query refused: rate limit exceeded",
}


@dataclass(frozen=True)
class Blocklist:
    """One DNS blocklist and how to read its answers."""

    name: str
    zone: str
    kind: str  # "ip" or "domain"
    delist_url: str | None
    access: str
    test_entry: str
    listed_codes: frozenset[str] | None = None  # None: any 127.x answer that is not an error
    error_codes: dict[str, str] = field(default_factory=dict)
    ipv6: bool = False
    retired: bool = False


BLOCKLISTS: tuple[Blocklist, ...] = (
    Blocklist(
        "Spamhaus ZEN",
        "zen.spamhaus.org",
        "ip",
        "https://check.spamhaus.org/",
        "Free for low-volume, non-commercial use through your own resolver. Public resolvers are "
        "refused; commercial use needs a Spamhaus Data Query Service (DQS) key.",
        "127.0.0.2",
        error_codes=_SPAMHAUS_ERRORS,
        ipv6=True,
    ),
    Blocklist(
        "Barracuda BRBL",
        "b.barracudacentral.org",
        "ip",
        "https://www.barracudacentral.org/rbl/removal-request",
        "Free. Barracuda asks heavy users to register their resolver IPs at barracudacentral.org.",
        "127.0.0.2",
    ),
    Blocklist(
        "SpamCop",
        "bl.spamcop.net",
        "ip",
        "https://www.spamcop.net/bl.shtml",
        "Free. Listings expire automatically about 24 hours after spam reports stop.",
        "127.0.0.2",
    ),
    Blocklist(
        "SORBS",
        "dnsbl.sorbs.net",
        "ip",
        None,
        "Retired: Proofpoint shut SORBS down in 2024 and its zones no longer answer. Skipped "
        "unless --include-retired is set.",
        "127.0.0.2",
        retired=True,
    ),
    Blocklist(
        "PSBL",
        "psbl.surriel.com",
        "ip",
        "https://psbl.org/",
        "Free, with self-service removal.",
        "127.0.0.2",
    ),
    Blocklist(
        "Mailspike BL",
        "bl.mailspike.net",
        "ip",
        "https://mailspike.org/iplookup.html",
        "Free for low volume. Only 127.0.0.2 means listed; 127.0.0.10-14 are reputation scores.",
        "127.0.0.2",
        listed_codes=frozenset({"127.0.0.2"}),
    ),
    Blocklist(
        "UCEPROTECT L1",
        "dnsbl-1.uceprotect.net",
        "ip",
        "https://www.uceprotect.net/en/rblcheck.php",
        "Free to query. Listings expire automatically once abuse stops; paid express delisting "
        "is optional and never required.",
        "127.0.0.2",
    ),
    Blocklist(
        "Spamhaus DBL",
        "dbl.spamhaus.org",
        "domain",
        "https://check.spamhaus.org/",
        "Same terms as Spamhaus ZEN: your own resolver for low volume, DQS key for commercial use.",
        "dbltest.com",
        error_codes=_SPAMHAUS_ERRORS,
    ),
    Blocklist(
        "SURBL",
        "multi.surbl.org",
        "domain",
        "https://www.surbl.org/surbl-analysis",
        "Free for low-volume use; high-volume users need a data feed subscription.",
        "test.surbl.org",
        error_codes={"127.0.0.1": "query refused: access blocked for this resolver"},
    ),
    Blocklist(
        "URIBL",
        "multi.uribl.com",
        "domain",
        "https://admin.uribl.com/",
        "Free for low-volume use. Answers 127.0.0.1 when a resolver is over its query limit.",
        "test.uribl.com",
        error_codes={"127.0.0.1": "query refused: resolver over URIBL's free query limit"},
    ),
)


@dataclass
class ListResult:
    """The outcome of checking one target against one blocklist."""

    name: str
    zone: str
    status: str
    message: str
    codes: list[str] = field(default_factory=list)
    delist_url: str | None = None
    access: str = ""


def query_name(target: str, blocklist: Blocklist) -> str:
    """Build the DNS name to query for ``target`` on ``blocklist``."""
    if blocklist.kind == "ip":
        return f"{reverse_ip(target)}.{blocklist.zone}"
    return f"{normalize_domain(target)}.{blocklist.zone}"


def _lookup(client: DNSClient, target: str, blocklist: Blocklist) -> tuple[str, list[str], str]:
    """Return ``(status, codes, message)`` for one query, never raising."""
    try:
        codes = sorted(client.a(query_name(target, blocklist)))
    except DNSLookupError as exc:
        return ERROR, [], f"lookup failed: {exc.reason}"
    except Exception as exc:  # never let one list crash the whole run
        return ERROR, [], f"lookup failed: {type(exc).__name__}"
    errors = [blocklist.error_codes[c] for c in codes if c in blocklist.error_codes]
    if errors:
        return ERROR, codes, errors[0]
    listed = [
        c
        for c in codes
        if c.startswith("127.") and (blocklist.listed_codes is None or c in blocklist.listed_codes)
    ]
    if listed:
        return LISTED, codes, f"listed (return code {', '.join(listed)})"
    return CLEAN, codes, "not listed"


def check_list(
    client: DNSClient, target: str, blocklist: Blocklist, verify: bool = True
) -> ListResult:
    """Check ``target`` on one blocklist, optionally verifying the list answers its test entry."""
    base = {"delist_url": blocklist.delist_url, "access": blocklist.access}
    status, codes, message = _lookup(client, target, blocklist)
    if status == CLEAN and verify:
        test_status, _, _ = _lookup(client, blocklist.test_entry, blocklist)
        if test_status != LISTED:
            return ListResult(
                blocklist.name,
                blocklist.zone,
                UNVERIFIED,
                "no listing returned, but the list failed its own test query: result untrusted",
                codes,
                **base,
            )
    return ListResult(blocklist.name, blocklist.zone, status, message, codes, **base)


def lists_for(target: str) -> list[Blocklist]:
    """Return the blocklists that apply to ``target`` (an IP address or a domain)."""
    if is_ip_address(target):
        v6 = ":" in target
        return [b for b in BLOCKLISTS if b.kind == "ip" and (b.ipv6 or not v6)]
    return [b for b in BLOCKLISTS if b.kind == "domain"]


def _to_finding(result: ListResult) -> Finding:
    if result.status == LISTED:
        return Finding(
            result.name,
            Status.FAIL,
            f"Listed on {result.name} ({', '.join(result.codes)}).",
            f"Fix the cause first (compromised form or account, purchased or stale list, spam "
            f"trap hits), then request removal: {result.delist_url}",
            "Blocklists",
            weight=2,
        )
    if result.status == CLEAN:
        return Finding(result.name, Status.PASS, "Not listed.", None, "Blocklists")
    if result.status == SKIPPED:
        return Finding(result.name, Status.INFO, result.message, None, "Blocklists", weight=0)
    return Finding(
        result.name,
        Status.WARN,
        result.message[0].upper() + result.message[1:] + ".",
        "Rerun with --nameserver pointing at your own recursive resolver (not 8.8.8.8 or "
        "1.1.1.1), or a longer --timeout.",
        "Blocklists",
        weight=0,  # an unanswered query says nothing about your reputation; do not grade it
    )


def check_target(
    target: str,
    client: DNSClient | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    verify: bool = True,
    include_retired: bool = False,
    blocklists: Sequence[Blocklist] | None = None,
) -> dict[str, Any]:
    """Check an IP or domain against every applicable blocklist and return the result dict.

    Args:
        target: An IPv4/IPv6 address or a domain name.
        client: DNS client to use (defaults to the system resolver with ``timeout``).
        timeout: Per-query timeout in seconds.
        verify: Also query each list's test entry to detect refused or blocked queries.
        include_retired: Query lists that have shut down (they are skipped by default).
        blocklists: Override the lists to check (defaults to :data:`BLOCKLISTS`).
    """
    target = target.strip()
    if not is_ip_address(target):
        target = normalize_domain(target)
    client = client or DNSClient(timeout=timeout)
    applicable = list(blocklists) if blocklists is not None else lists_for(target)

    active = [b for b in applicable if include_retired or not b.retired]
    with ThreadPoolExecutor(max_workers=max(1, min(8, len(active)))) as pool:
        checked = list(pool.map(lambda b: check_list(client, target, b, verify), active))
    skipped = [
        ListResult(b.name, b.zone, SKIPPED, "Skipped: this list has been retired.", [],
                   b.delist_url, b.access)
        for b in applicable
        if b.retired and not include_retired
    ]  # fmt: skip
    results = checked + skipped
    findings = [_to_finding(r) for r in results]
    listed = [r for r in results if r.status == LISTED]
    uncertain = [r for r in results if r.status in {ERROR, UNVERIFIED}]
    score = score_findings(findings)
    if listed:
        summary = f"Listed on {len(listed)} of {len(checked)} blocklists."
    else:
        summary = f"Not listed on any of the {len(checked) - len(uncertain)} lists that answered."
    if uncertain:
        summary += f" {len(uncertain)} list(s) could not give a trustworthy answer."
    return envelope(
        "blacklist",
        target,
        target_type="ip" if is_ip_address(target) else "domain",
        score=score,
        grade=grade(score),
        summary=summary,
        listed_count=len(listed),
        results=[asdict(r) for r in results],
        findings=[f.to_dict() for f in findings],
    )


def render(result: dict[str, Any]) -> str:
    """Render blocklist results for the terminal."""
    labels = {LISTED: "LISTED", CLEAN: "not listed", ERROR: "ERROR", UNVERIFIED: "UNVERIFIED",
              SKIPPED: "skipped"}  # fmt: skip
    body = table(
        ["List", "Zone", "Result", "Details"],
        [
            [
                r["name"],
                r["zone"],
                labels[r["status"]],
                "" if r["status"] == CLEAN else r["message"],
            ]
            for r in result["results"]
        ],
    )
    lines = [
        heading(f"Blocklist check: {result['target']} ({result['target_type']})"),
        f"{grade_badge(result['grade'], result['score'])}   {result['summary']}",
        "",
        body,
    ]
    listed = [r for r in result["results"] if r["status"] == LISTED]
    if listed:
        lines += ["", subheading("Delisting")]
        lines += [f"  {r['name']}: {r['delist_url']}" for r in listed]
    if result["target_type"] == "domain":
        lines += [
            "",
            "Tip: to check your sending IPs, run `deliv header-analyze` on a delivered message to "
            "find them, then `deliv blacklist <ip>`.",
        ]
    return "\n".join(lines)


def command(
    target: Annotated[
        str, typer.Argument(help="A sending IP address (e.g. 192.0.2.25) or a domain.")
    ],
    timeout: TimeoutOption = DEFAULT_TIMEOUT,
    nameserver: NameserverOption = None,
    verify: Annotated[
        bool,
        typer.Option(
            "--verify/--no-verify",
            help="Also ask each list about its own test entry, so refused queries are not "
            "mistaken for a clean result.",
        ),
    ] = True,
    include_retired: Annotated[
        bool,
        typer.Option("--include-retired", help="Also query lists that have shut down (SORBS)."),
    ] = False,
    as_json: JsonFlag = False,
) -> None:
    """Check whether an IP address or domain is on the major email blocklists.

    Shows listed / not listed for each list and a delisting link for every listing. Lists that
    time out, rate-limit, or refuse your DNS resolver are flagged as warnings, not crashes.
    """
    client = DNSClient(timeout=timeout, nameservers=nameserver)
    result = check_target(
        target, client=client, timeout=timeout, verify=verify, include_retired=include_retired
    )
    emit(result, as_json, render)
