"""``deliv warmup-plan``: a day-by-day ramp schedule for a new sending IP or domain.

Volume grows geometrically from ``--start-volume`` to ``--target-volume`` over ``--days``, but never
faster than the mailbox provider's growth guidance allows. If the target cannot be reached safely
in the requested days, the plan is extended and says so.

This is planning guidance, not a guarantee of inbox placement. Mailbox providers decide placement
from engagement and complaints, not from the calendar, so every day of the plan comes with the
audience to send to and the health gates to pass before moving on.
"""

import math
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Annotated, Any

import typer

from deliv.lib.options import JsonFlag
from deliv.lib.output import emit, envelope, heading, subheading, table
from deliv.lib.scoring import Finding, Status

MAX_PLAN_DAYS = 120

DISCLAIMER = (
    "Planning guidance, not a guarantee of inbox placement. Mailbox providers place mail based "
    "on engagement, complaints, and authentication; adjust daily based on your results."
)

GATES = (
    "Advance to the next day's volume only if the previous day had a bounce rate under 2%, a "
    "spam complaint rate under 0.1%, and no spike in 4xx deferrals. Otherwise repeat the "
    "previous day's volume until the numbers recover."
)


class ESP(str, Enum):
    """Mailbox provider profiles with their own ramp guidance."""

    gmail = "gmail"
    outlook = "outlook"
    yahoo = "yahoo"
    generic = "generic"


@dataclass(frozen=True)
class Profile:
    """Ramp guidance for one mailbox provider."""

    label: str
    first_day_max: int
    max_daily_growth: float
    notes: tuple[str, ...]


PROFILES: dict[ESP, Profile] = {
    ESP.gmail: Profile(
        "Gmail",
        first_day_max=200,
        max_daily_growth=1.5,
        notes=(
            "Register the domain in Google Postmaster Tools before day 1 and check domain and "
            "IP reputation daily.",
            "Gmail's sender guidelines require a user-reported spam rate below 0.3%; aim for "
            "under 0.1%.",
            "Opens, replies, and 'not spam' moves build reputation; volume alone does not.",
        ),
    ),
    ESP.outlook: Profile(
        "Outlook.com / Microsoft 365",
        first_day_max=150,
        max_daily_growth=1.3,
        notes=(
            "Enroll the sending IPs in Microsoft SNDS and JMRP before day 1.",
            "Microsoft throttles new IPs hard: expect 4.7.650 / 4.7.500 deferrals and retry "
            "them slowly instead of pushing more volume.",
            "Ramp more slowly than for Gmail; Microsoft weighs consistency heavily.",
        ),
    ),
    ESP.yahoo: Profile(
        "Yahoo / AOL",
        first_day_max=200,
        max_daily_growth=1.5,
        notes=(
            "Sign up for the Yahoo Complaint Feedback Loop (CFL) and suppress every complainer.",
            "TSS04 deferrals mean slow down: hold volume flat until they clear.",
            "Yahoo requires one-click unsubscribe and DMARC for bulk senders.",
        ),
    ),
    ESP.generic: Profile(
        "Mixed / generic",
        first_day_max=500,
        max_daily_growth=2.0,
        notes=(
            "Split the daily volume across providers in proportion to your list, and follow "
            "the strictest provider's pace if one starts deferring.",
            "Watch bounces and complaints per provider, not just in total.",
        ),
    ),
}

#: (share of the plan completed, audience guidance) in order.
AUDIENCE_STAGES: tuple[tuple[float, str], ...] = (
    (0.25, "Engaged in the last 30 days"),
    (0.50, "Engaged in the last 60 days"),
    (0.80, "Engaged in the last 90 days"),
    (1.01, "Engaged in the last 180 days"),
)


@dataclass
class PlanDay:
    """One day of the ramp."""

    day: int
    volume: int
    growth: float | None
    audience: str


def _step(value: float) -> int:
    for limit, step in ((100, 5), (1_000, 10), (10_000, 50), (100_000, 100)):
        if value < limit:
            return step
    return 1_000


def nice_round(value: float) -> int:
    """Round a volume to a number that is easy to configure in an ESP."""
    step = _step(value)
    return max(1, int(round(value / step) * step))


def nice_floor(value: float) -> int:
    """Round a volume down to a friendly number (never above ``value``)."""
    step = _step(value)
    return max(1, int(math.floor(value / step) * step))


def _audience(day: int, total: int) -> str:
    share = day / total
    return next(label for limit, label in AUDIENCE_STAGES if share <= limit)


def build_plan(
    start: int, target: int, days: int, profile: Profile
) -> tuple[list[PlanDay], dict[str, Any]]:
    """Build the ramp and return ``(plan_days, meta)``.

    Each day's growth is recomputed from where the ramp actually is, so rounding to friendly
    numbers never drifts the plan off target. Growth never exceeds ``profile.max_daily_growth``;
    when that makes ``days`` too short, the plan is extended (up to :data:`MAX_PLAN_DAYS`).
    """
    effective_start = min(start, profile.first_day_max, target)
    volumes: list[int] = [effective_start]
    while volumes[-1] < target and len(volumes) < MAX_PLAN_DAYS:
        previous = volumes[-1]
        remaining = days - len(volumes)
        needed = (target / previous) ** (1 / remaining) if remaining > 0 else math.inf
        proposed = nice_round(previous * min(needed, profile.max_daily_growth))
        proposed = min(proposed, nice_floor(previous * profile.max_daily_growth), target)
        volumes.append(max(previous + 1, proposed))
    while 1 < len(volumes) < days:
        volumes.append(volumes[-1])  # target reached early: hold steady

    plan = [
        PlanDay(
            day=index + 1,
            volume=volume,
            growth=None if index == 0 else round(volume / volumes[index - 1], 2),
            audience=_audience(index + 1, len(volumes)),
        )
        for index, volume in enumerate(volumes)
    ]
    growth = (volumes[-1] / effective_start) ** (1 / (len(volumes) - 1)) if len(volumes) > 1 else 1
    meta = {
        "effective_start": effective_start,
        "start_clamped": effective_start < start and effective_start < target,
        "daily_growth": round(growth, 3),
        "max_daily_growth": profile.max_daily_growth,
        "requested_days": days,
        "plan_days": len(plan),
        "extended": len(plan) > days,
        "reaches_target": volumes[-1] >= target,
    }
    return plan, meta


def make_plan(esp: ESP | str, start: int, target: int, days: int) -> dict[str, Any]:
    """Build a warmup plan and return the result dict."""
    esp = ESP(esp)
    if start < 1 or target < 1 or days < 1:
        raise ValueError("start volume, target volume, and days must all be at least 1")
    profile = PROFILES[esp]
    plan, meta = build_plan(start, target, min(days, MAX_PLAN_DAYS), profile)

    findings: list[Finding] = []
    if meta["start_clamped"]:
        findings.append(
            Finding(
                "Starting volume",
                Status.WARN,
                f"Day 1 lowered from {start:,} to {meta['effective_start']:,}: more than "
                f"{profile.first_day_max:,} on a cold IP/domain to {profile.label} invites "
                "throttling.",
                "Start small with your most engaged subscribers; the ramp catches up quickly.",
                "Warmup",
            )
        )
    if meta["extended"]:
        findings.append(
            Finding(
                "Ramp length",
                Status.WARN,
                f"Reaching {target:,}/day in {days} days would need "
                f"{((target / meta['effective_start']) ** (1 / max(days - 1, 1)) - 1):.0%} daily "
                f"growth; {profile.label} guidance caps it near "
                f"{profile.max_daily_growth - 1:.0%}. The plan runs {meta['plan_days']} days.",
                "Keep the longer ramp, or split volume across more IPs or sending subdomains.",
                "Warmup",
            )
        )
    if not meta["reaches_target"]:
        findings.append(
            Finding(
                "Target volume",
                Status.WARN,
                f"The {MAX_PLAN_DAYS}-day plan ends at {plan[-1].volume:,}/day, short of "
                f"{target:,}.",
                "Warm additional IPs or subdomains in parallel.",
                "Warmup",
            )
        )
    if not findings and len(plan) == 1:
        findings.append(
            Finding(
                "Ramp length",
                Status.PASS,
                f"{target:,}/day is a safe day-1 volume for {profile.label}; no ramp needed.",
                None,
                "Warmup",
            )
        )
    elif not findings:
        findings.append(
            Finding(
                "Ramp length",
                Status.PASS,
                f"Reaches {target:,}/day in {len(plan)} days at about "
                f"{meta['daily_growth'] - 1:.0%} daily growth, within {profile.label} guidance.",
                None,
                "Warmup",
            )
        )

    return envelope(
        "warmup-plan",
        f"{profile.label}: {meta['effective_start']:,} to {target:,}/day",
        esp=esp.value,
        esp_label=profile.label,
        start_volume=start,
        target_volume=target,
        summary=(
            f"{len(plan)}-day ramp from {meta['effective_start']:,} to {plan[-1].volume:,} "
            f"messages/day for {profile.label}."
        ),
        disclaimer=DISCLAIMER,
        gates=GATES,
        esp_notes=list(profile.notes),
        meta=meta,
        plan=[asdict(day) for day in plan],
        total_messages=sum(day.volume for day in plan),
        findings=[f.to_dict() for f in findings],
    )


def render(result: dict[str, Any]) -> str:
    """Render a warmup plan for the terminal."""
    rows = []
    last_audience = None
    for day in result["plan"]:
        audience = day["audience"] if day["audience"] != last_audience else ""
        last_audience = day["audience"]
        growth = "-" if day["growth"] is None else f"x{day['growth']:.2f}"
        rows.append([day["day"], f"{day['volume']:,}", growth, audience])
    lines = [
        heading(f"Warmup plan: {result['esp_label']}"),
        typer.style(result["disclaimer"], fg=typer.colors.YELLOW),
        "",
        result["summary"],
    ]
    for finding in result["findings"]:
        if finding["status"] != "pass":
            lines.append(f"Note: {finding['message']} {finding['remediation']}")
    lines += [
        "",
        table(["Day", "Volume", "Growth", "Send to"], rows),
        f"Total messages across the ramp: {result['total_messages']:,}",
        "",
        subheading("Daily gate"),
        f"  {result['gates']}",
        "",
        subheading(f"{result['esp_label']} notes"),
    ]
    lines += [f"  - {note}" for note in result["esp_notes"]]
    return "\n".join(lines)


def command(
    target_volume: Annotated[
        int,
        typer.Option("--target-volume", min=1, help="Messages per day you want to reach."),
    ],
    esp: Annotated[
        ESP,
        typer.Option("--esp", help="Which mailbox provider's pace to follow."),
    ] = ESP.generic,
    start_volume: Annotated[
        int,
        typer.Option("--start-volume", min=1, help="Messages to send on day 1."),
    ] = 50,
    days: Annotated[
        int,
        typer.Option(
            "--days",
            min=1,
            max=MAX_PLAN_DAYS,
            help="How many days you want the ramp "
            "to take. Extended automatically if that would be too fast.",
        ),
    ] = 30,
    as_json: JsonFlag = False,
) -> None:
    """Plan a day-by-day sending ramp for a new IP or domain.

    Grows volume geometrically without outpacing the mailbox provider's guidance, and says who to
    send to each day (most engaged first). Planning guidance, not a guarantee of inbox placement.
    """
    emit(make_plan(esp, start_volume, target_volume, days), as_json, render)
