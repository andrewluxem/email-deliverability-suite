"""``deliv bounce-classify``: turn a bounce message into a suppression decision.

Accepts an enhanced status code (``5.1.1``), a DSN snippet, or raw bounce text, and classifies it as
a hard bounce, soft bounce, or block (policy or reputation). Rules are tried in this order, first
match wins:

1. Mailbox-provider message patterns (Gmail, Microsoft, Yahoo, and others).
2. Specific RFC 3463 enhanced status codes (``5.1.1``, ``4.2.2``, ``5.7.26``...).
3. Generic bounce phrases (``user unknown``, ``mailbox full``, ``blocked``...).
4. RFC 3463 status-code classes (``5.1.x``, ``4.x.x``...).
5. The basic SMTP reply code (``550``, ``421``...).

Each classification maps to an action: ``suppress`` (never mail again), ``retry`` (with backoff),
or ``investigate`` (fix something on the sending side first). Designed to be piped: ``--json``
output is stable, and ``--batch`` classifies one bounce per input line.
"""

import re
import sys
from dataclasses import dataclass
from typing import Annotated, Any

import typer

from deliv.lib.options import JsonFlag
from deliv.lib.output import emit, envelope, heading, table
from deliv.lib.scoring import Finding, Status

HARD, SOFT, BLOCK, UNKNOWN = "hard", "soft", "block", "unknown"
SUPPRESS, RETRY, INVESTIGATE = "suppress", "retry", "investigate"

#: Suggested retry backoff for soft bounces, in minutes after the first failure.
RETRY_SCHEDULE_MINUTES = (15, 60, 240, 720, 1440)
#: Suppress an address after this many consecutive soft bounces.
SOFT_BOUNCE_SUPPRESS_AFTER = 3

_ACTION_NOTES = {
    SUPPRESS: "Suppress this address now; mailing it again hurts sender reputation.",
    RETRY: (
        f"Retry with backoff ({', '.join(f'{m}m' for m in RETRY_SCHEDULE_MINUTES)}); suppress "
        f"after {SOFT_BOUNCE_SUPPRESS_AFTER} consecutive soft bounces across 72 hours."
    ),
    INVESTIGATE: "Do not suppress yet: fix the sending-side cause, then resend.",
}


@dataclass(frozen=True)
class Rule:
    """A classification rule: a pattern plus the verdict it produces."""

    id: str
    pattern: re.Pattern[str]
    classification: str
    action: str
    description: str
    provider: str | None = None


def _rule(
    rule_id: str,
    pattern: str,
    classification: str,
    action: str,
    description: str,
    provider: str | None = None,
) -> Rule:
    return Rule(
        rule_id,
        re.compile(pattern, re.IGNORECASE),
        classification,
        action,
        description,
        provider,
    )


PROVIDER_RULES: tuple[Rule, ...] = (
    # Gmail
    _rule("gmail-no-such-user", r"account that you tried to reach does not exist", HARD, SUPPRESS,
          "Gmail: the mailbox does not exist.", "Gmail"),
    _rule("gmail-disabled", r"account that you tried to reach is disabled", HARD, SUPPRESS,
          "Gmail: the account is disabled.", "Gmail"),
    _rule("gmail-over-quota", r"(?:inbox|account).{0,40}(?:out of storage|over quota)", SOFT,
          RETRY, "Gmail: the recipient's mailbox is full.", "Gmail"),
    _rule("gmail-rate-limited", r"receiving mail (?:at a rate|too quickly)", SOFT, RETRY,
          "Gmail: the recipient is receiving mail too fast; slow down.", "Gmail"),
    _rule("gmail-unauthenticated", r"unauthenticated email|sender is unauthenticated", BLOCK,
          INVESTIGATE,
          "Gmail: the message failed SPF/DKIM/DMARC authentication.", "Gmail"),
    _rule("gmail-spf-dkim", r"5\.7\.27|sender (?:address|domain) does not pass spf", BLOCK,
          INVESTIGATE, "Gmail: SPF did not pass for the sending domain.", "Gmail"),
    _rule("gmail-unsolicited", r"unusual rate of unsolicited mail|likely unsolicited mail|"
          r"low reputation of the sending", BLOCK, INVESTIGATE,
          "Gmail: blocked for spam or low sender reputation.", "Gmail"),
    _rule("gmail-ipv6", r"IPv6 sending guidelines", BLOCK, INVESTIGATE,
          "Gmail: the IPv6 sender lacks PTR records or authentication.", "Gmail"),
    # Microsoft (Outlook.com / Hotmail / Microsoft 365)
    _rule("microsoft-blocklist", r"\bS31[1-5]\d\b|on our block list", BLOCK,
          INVESTIGATE, "Microsoft: the sending IP is on Microsoft's block list (delist via the "
          "Outlook.com sender support form).", "Microsoft"),
    _rule("microsoft-mailbox-unavailable", r"5\.5\.0 .*mailbox unavailable|RecipientNotFound|"
          r"Recipient address rejected: Access denied", HARD, SUPPRESS,
          "Microsoft: the recipient does not exist.", "Microsoft"),
    _rule("microsoft-ip-reputation", r"4\.7\.650|4\.7\.500|IP reputation|temporarily rate "
          r"limited", BLOCK, RETRY, "Microsoft: throttled for IP reputation; slow down and retry.",
          "Microsoft"),
    _rule("microsoft-access-denied", r"5\.7\.(?:606|705|708|750)|traffic not accepted from this "
          r"IP|banned sending IP", BLOCK, INVESTIGATE,
          "Microsoft: the sending IP or tenant is blocked.", "Microsoft"),
    # Yahoo / AOL
    _rule("yahoo-no-account", r"doesn'?t have an? (?:yahoo|aol|ymail)\.com account|"
          r"delivery error: dd ", HARD, SUPPRESS, "Yahoo/AOL: the mailbox does not exist.",
          "Yahoo"),
    _rule("yahoo-deferred", r"\[TS(?:S)?0[1-4]\]|temporarily deferred due to unexpected volume "
          r"or user complaints", BLOCK, RETRY,
          "Yahoo: deferred for volume or complaints; slow down and retry.", "Yahoo"),
    _rule("yahoo-permanent", r"\[TSS09\]|permanently deferred", BLOCK, INVESTIGATE,
          "Yahoo: permanently deferred for reputation; stop sending and fix the cause.", "Yahoo"),
    _rule("yahoo-policy", r"5\.7\.9 .*policy reasons|not accepted for policy reasons", BLOCK,
          INVESTIGATE, "Yahoo: rejected for policy or content reasons.", "Yahoo"),
    # Apple iCloud
    _rule("icloud-no-user", r"icloud\.com.*(?:user unknown|does not exist)|"
          r"5\.1\.1 <[^>]*@(?:icloud|me|mac)\.com>", HARD, SUPPRESS,
          "iCloud: the mailbox does not exist.", "Apple"),
)  # fmt: skip

#: Exact enhanced status codes with a well-understood meaning.
SPECIFIC_CODES: dict[str, tuple[str, str, str]] = {
    "5.1.0": (HARD, SUPPRESS, "Bad destination address."),
    "5.1.1": (HARD, SUPPRESS, "Bad destination mailbox: the address does not exist."),
    "5.1.2": (HARD, SUPPRESS, "Bad destination system: the domain does not exist or has no MX."),
    "5.1.3": (HARD, SUPPRESS, "Bad destination mailbox address syntax."),
    "5.1.6": (HARD, SUPPRESS, "The mailbox has moved and left no forwarding address."),
    "5.1.10": (HARD, SUPPRESS, "The recipient domain publishes a null MX: it accepts no mail."),
    "5.1.7": (BLOCK, INVESTIGATE, "The sender address syntax was rejected."),
    "5.1.8": (BLOCK, INVESTIGATE, "The sender's domain was rejected (check it resolves)."),
    "5.2.1": (HARD, SUPPRESS, "The mailbox is disabled and not accepting messages."),
    "4.2.1": (SOFT, RETRY, "The mailbox is temporarily unavailable or rate limited."),
    "4.2.2": (SOFT, RETRY, "The mailbox is full."),
    "5.2.2": (SOFT, RETRY, "The mailbox is full."),
    "5.2.3": (SOFT, INVESTIGATE, "The message is larger than the mailbox accepts."),
    "5.3.4": (SOFT, INVESTIGATE, "The message is too large for the receiving system."),
    "5.4.1": (HARD, SUPPRESS, "No answer from host, or the recipient was rejected."),
    "5.4.4": (HARD, SUPPRESS, "Unable to route: the recipient domain has no mail route."),
    "5.4.7": (SOFT, RETRY, "Delivery time expired after repeated temporary failures."),
    "4.4.7": (SOFT, RETRY, "Delivery time expired after repeated temporary failures."),
    "5.7.1": (BLOCK, INVESTIGATE, "Delivery not authorized: blocked by policy or reputation."),
    "4.7.1": (BLOCK, RETRY, "Temporarily blocked by policy or reputation."),
    "4.7.0": (BLOCK, RETRY, "Temporary security or policy rejection (often rate limiting)."),
    "5.7.13": (HARD, SUPPRESS, "The user account is disabled."),
    "5.7.23": (BLOCK, INVESTIGATE, "SPF validation failed."),
    "5.7.25": (BLOCK, INVESTIGATE, "Reverse DNS (PTR) validation failed for the sending IP."),
    "5.7.26": (BLOCK, INVESTIGATE, "Multiple authentication checks failed (DMARC)."),
    "5.7.27": (BLOCK, INVESTIGATE, "The sender domain has a null MX."),
}

#: Fallbacks by status-code class and subject (RFC 3463 section 3).
CODE_CLASSES: tuple[tuple[str, str, str, str], ...] = (
    ("5.1", HARD, SUPPRESS, "Permanent addressing failure."),
    ("4.1", SOFT, RETRY, "Temporary addressing failure."),
    ("5.2", HARD, SUPPRESS, "Permanent mailbox failure."),
    ("4.2", SOFT, RETRY, "Temporary mailbox failure."),
    ("5.3", SOFT, INVESTIGATE, "Receiving mail system problem."),
    ("4.3", SOFT, RETRY, "Temporary receiving mail system problem."),
    ("5.4", HARD, SUPPRESS, "Permanent network or routing failure."),
    ("4.4", SOFT, RETRY, "Temporary network or routing failure."),
    ("5.5", SOFT, INVESTIGATE, "SMTP protocol error on the sending side."),
    ("4.5", SOFT, RETRY, "Temporary SMTP protocol error."),
    ("5.6", BLOCK, INVESTIGATE, "Message content or media was rejected."),
    ("4.6", SOFT, RETRY, "Temporary content conversion problem."),
    ("5.7", BLOCK, INVESTIGATE, "Rejected by security or policy."),
    ("4.7", BLOCK, RETRY, "Temporarily rejected by security or policy."),
    ("5", HARD, SUPPRESS, "Permanent failure."),
    ("4", SOFT, RETRY, "Temporary failure."),
)

GENERIC_RULES: tuple[Rule, ...] = (
    _rule("text-user-unknown", r"user unknown|unknown user|no such (?:user|mailbox|recipient)|"
          r"unknown recipient|recipient unknown|invalid (?:recipient|mailbox|address)|recipient "
          r"(?:not found|rejected)|mailbox (?:not found|does not exist|unavailable)|address "
          r"rejected|does not exist|no mailbox here|not a valid mailbox|account (?:has been )?"
          r"(?:disabled|deactivated|closed)|unrouteable address", HARD, SUPPRESS,
          "The recipient address does not exist."),
    _rule("text-bad-domain", r"domain (?:not found|does not exist)|host (?:or domain name )?not "
          r"found|no mx (?:record|host)|name service error|nxdomain", HARD, SUPPRESS,
          "The recipient domain does not accept mail."),
    _rule("text-blocklisted", r"black ?list|block ?list|listed (?:at|on|in|by)|spamhaus|"
          r"barracuda|spamcop|\bdnsbl\b|\brbl\b", BLOCK, INVESTIGATE,
          "The sending IP or domain is on a blocklist."),
    _rule("text-auth", r"\bdmarc\b|\bspf\b.{0,20}(?:fail|reject)|\bdkim\b.{0,20}(?:fail|invalid)|"
          r"not authenticated|authentication (?:required|failed)|reverse dns|\bptr\b", BLOCK,
          INVESTIGATE,
          "The message failed sender authentication."),
    _rule("text-spam", r"\bspam\b|unsolicited|junk mail|content (?:rejected|filter)|"
          r"message (?:rejected|refused) (?:as|due to)|poor reputation|reputation", BLOCK,
          INVESTIGATE, "The message was rejected as spam or for reputation."),
    _rule("text-policy", r"policy (?:reasons?|violation|rejection)|not (?:authorized|permitted)|"
          r"access denied|relay(?:ing)? denied|blocked", BLOCK, INVESTIGATE,
          "The receiving server's policy blocked the message."),
    _rule("text-mailbox-full", r"mailbox (?:is )?full|over ?quota|quota exceeded|exceeded "
          r"(?:storage|quota)|insufficient (?:system )?storage|out of storage", SOFT, RETRY,
          "The recipient's mailbox is full."),
    _rule("text-temporary", r"greylist|graylist|try (?:again )?later|temporar(?:y|ily)|"
          r"deferred|timed? ?out|too many (?:connections|messages)|rate limit|throttl|"
          r"service (?:not )?(?:un)?available|connection (?:refused|reset|lost)", SOFT, RETRY,
          "A temporary delivery failure."),
)  # fmt: skip

_ENHANCED_RE = re.compile(r"(?<![\d.])([245])\.(\d{1,3})\.(\d{1,3})(?![\d.])")
_REPLY_RE = re.compile(r"(?<![\d.])([245]\d\d)(?:[ -]|$)")


def extract_codes(text: str) -> tuple[str | None, str | None]:
    """Return ``(enhanced_status_code, smtp_reply_code)`` found in ``text`` (either may be None)."""
    enhanced = _ENHANCED_RE.search(text)
    reply = _REPLY_RE.search(text)
    return (
        ".".join(enhanced.groups()) if enhanced else None,
        reply.group(1) if reply else None,
    )


def classify(text: str) -> dict[str, Any]:
    """Classify one bounce (code, DSN snippet, or raw text) and return a plain dict."""
    text = " ".join(text.split())
    enhanced, reply = extract_codes(text)
    decision = _decide(text, enhanced, reply)
    classification, action, rule_id, source, description, provider, confidence = decision
    return {
        "input": text,
        "classification": classification,
        "action": action,
        "action_detail": _ACTION_NOTES.get(action, "Review manually."),
        "status_code": enhanced,
        "smtp_code": reply,
        "provider": provider,
        "rule": {"id": rule_id, "source": source, "description": description},
        "confidence": confidence,
        "retry_after_minutes": list(RETRY_SCHEDULE_MINUTES) if action == RETRY else [],
    }


def _decide(
    text: str, enhanced: str | None, reply: str | None
) -> tuple[str, str, str, str, str, str | None, str]:
    for rule in PROVIDER_RULES:
        if rule.pattern.search(text):
            return (
                rule.classification,
                rule.action,
                rule.id,
                "provider",
                rule.description,
                rule.provider,
                "high",
            )
    if enhanced and enhanced in SPECIFIC_CODES:
        classification, action, description = SPECIFIC_CODES[enhanced]
        return (classification, action, f"rfc3463-{enhanced}", "rfc3463", description, None, "high")
    for rule in GENERIC_RULES:
        if rule.pattern.search(text):
            if rule.classification == HARD and (enhanced or reply or "5").startswith("4"):
                # A temporary code overrides "does not exist"-style wording.
                return (
                    SOFT,
                    RETRY,
                    rule.id,
                    "pattern",
                    rule.description + " (temporary code)",
                    None,
                    "medium",
                )
            return (
                rule.classification,
                rule.action,
                rule.id,
                "pattern",
                rule.description,
                None,
                "medium",
            )
    if enhanced:
        cls, subject = enhanced.split(".")[:2]
        for prefix, classification, action, description in CODE_CLASSES:
            if prefix in (f"{cls}.{subject}", cls):
                return (
                    classification,
                    action,
                    f"rfc3463-{prefix}.x",
                    "rfc3463",
                    description,
                    None,
                    "medium",
                )
    if reply:
        if reply.startswith("5"):
            return (
                HARD,
                SUPPRESS,
                f"smtp-{reply}",
                "smtp-code",
                "Permanent SMTP failure with no further detail.",
                None,
                "low",
            )
        if reply.startswith("4"):
            return (
                SOFT,
                RETRY,
                f"smtp-{reply}",
                "smtp-code",
                "Temporary SMTP failure with no further detail.",
                None,
                "low",
            )
    return (
        UNKNOWN,
        INVESTIGATE,
        "unmatched",
        "none",
        "No status code or known bounce phrase found.",
        None,
        "low",
    )


def _finding(result: dict[str, Any]) -> Finding:
    status = {HARD: Status.FAIL, BLOCK: Status.FAIL, SOFT: Status.WARN}.get(
        result["classification"], Status.WARN
    )
    return Finding(
        "Bounce",
        status,
        f"{result['classification'].upper()} bounce: {result['rule']['description']}",
        result["action_detail"],
        "Bounces",
        details={"rule": result["rule"]["id"]},
    )


def classify_one(text: str) -> dict[str, Any]:
    """Classify a single bounce and wrap it in the standard result envelope."""
    result = classify(text)
    label = result["status_code"] or result["smtp_code"] or text[:60]
    return envelope(
        "bounce-classify",
        label,
        summary=f"{result['classification']} bounce -> {result['action']}",
        **result,
        findings=[_finding(result).to_dict()],
    )


def classify_batch(lines: list[str]) -> dict[str, Any]:
    """Classify one bounce per non-empty line and summarize the counts."""
    results = [classify(line) for line in lines if line.strip()]
    counts: dict[str, int] = {}
    for item in results:
        counts[item["classification"]] = counts.get(item["classification"], 0) + 1
    actions: dict[str, int] = {}
    for item in results:
        actions[item["action"]] = actions.get(item["action"], 0) + 1
    findings = [
        Finding(
            f"{name.capitalize()} bounces",
            Status.FAIL if name in {HARD, BLOCK} else Status.WARN,
            f"{count} of {len(results)} bounces classified as {name}.",
            _ACTION_NOTES[SUPPRESS if name == HARD else RETRY if name == SOFT else INVESTIGATE],
            "Bounces",
        ).to_dict()
        for name, count in sorted(counts.items())
    ]
    return envelope(
        "bounce-classify",
        f"{len(results)} bounces",
        summary=", ".join(f"{n} {c}" for c, n in sorted(counts.items())) or "no input",
        counts=counts,
        actions=actions,
        results=results,
        findings=findings,
    )


def render(result: dict[str, Any]) -> str:
    """Render a bounce classification (single or batch) for the terminal."""
    if "results" in result:
        return "\n".join(
            [
                heading(f"Bounce classification: {result['target']}"),
                f"Summary: {result['summary']}",
                "",
                table(
                    ["Class", "Action", "Code", "Rule", "Bounce"],
                    [
                        [
                            r["classification"],
                            r["action"],
                            r["status_code"] or r["smtp_code"] or "-",
                            r["rule"]["id"],
                            r["input"] if len(r["input"]) <= 50 else r["input"][:47] + "...",
                        ]
                        for r in result["results"]
                    ],
                ),
            ]
        )
    colors = {HARD: typer.colors.RED, BLOCK: typer.colors.RED, SOFT: typer.colors.YELLOW}
    label = typer.style(
        result["classification"].upper(), fg=colors.get(result["classification"]), bold=True
    )
    code = result["status_code"] or result["smtp_code"] or "none found"
    provider = f" ({result['provider']})" if result["provider"] else ""
    lines = [
        heading("Bounce classification"),
        f"Classification: {label}{provider}",
        f"Action:         {result['action']}",
        f"Status code:    {code}",
        f"Matched rule:   {result['rule']['id']} [{result['rule']['source']}], "
        f"confidence {result['confidence']}",
        f"Why:            {result['rule']['description']}",
        f"Next step:      {result['action_detail']}",
    ]
    return "\n".join(lines)


def command(
    bounce: Annotated[
        str | None,
        typer.Argument(
            help="The bounce: a status code like 5.1.1, a DSN line, or bounce text. Omit to read "
            "from stdin."
        ),
    ] = None,
    batch: Annotated[
        bool,
        typer.Option("--batch", help="Read many bounces from stdin, one per line."),
    ] = False,
    as_json: JsonFlag = False,
) -> None:
    """Classify a bounce as hard, soft, or block, and say what to do: suppress, retry, investigate.

    Recognizes RFC 3463 status codes and common Gmail, Microsoft, and Yahoo bounce messages. Use
    --json to pipe results into a suppression workflow.
    """
    if bounce is None:
        if sys.stdin is None or sys.stdin.isatty():
            typer.echo("Error: pass a bounce as an argument or pipe it on stdin.", err=True)
            raise typer.Exit(2)
        raw = sys.stdin.read()
    else:
        raw = bounce
    if batch:
        emit(classify_batch(raw.splitlines()), as_json, render)
    elif not raw.strip():
        typer.echo("Error: the bounce text is empty.", err=True)
        raise typer.Exit(2)
    else:
        emit(classify_one(raw), as_json, render)
