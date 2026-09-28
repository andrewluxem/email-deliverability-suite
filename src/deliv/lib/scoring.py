"""Shared 0-100 scoring and A-F grading used by every graded deliv tool.

Every tool reports its individual checks as :class:`Finding` objects. A finding has a status
(pass, warn, fail, or info), a weight, and an optional ``critical`` flag. The score is the
weighted share of points earned across scored findings:

* ``pass`` earns the full weight,
* ``warn`` earns half the weight,
* ``fail`` earns nothing,
* ``info`` is reported but never scored.

A failed critical finding (for example SPF ``+all``) caps the score at :data:`CRITICAL_CAP`, which
always grades F, no matter how good everything else looks.
"""

from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    """Outcome of a single check."""

    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    INFO = "info"


#: Points earned per unit of weight for each status. ``INFO`` is excluded from scoring.
STATUS_CREDIT: dict[Status, float] = {Status.PASS: 1.0, Status.WARN: 0.5, Status.FAIL: 0.0}

#: Highest score a result can reach when any critical finding failed.
CRITICAL_CAP = 40

#: Minimum score for each letter grade, checked in order.
GRADE_THRESHOLDS: tuple[tuple[int, str], ...] = ((90, "A"), (80, "B"), (70, "C"), (60, "D"))


@dataclass
class Finding:
    """One check result: what was tested, how it went, and how to fix it.

    Attributes:
        check: Short, stable name for the check (for example ``"SPF policy"``).
        status: Pass, warn, fail, or info.
        message: One plain-English sentence explaining the outcome.
        remediation: What to do about it. Required for every non-pass status that needs action.
        category: Grouping label (for example ``"SPF"`` or ``"DMARC"``).
        weight: Relative importance used by :func:`score_findings`.
        critical: When True and the finding fails, the overall score is capped.
        details: Extra structured data for ``--json`` consumers.
    """

    check: str
    status: Status
    message: str
    remediation: str | None = None
    category: str = ""
    weight: float = 1.0
    critical: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary representation."""
        data = asdict(self)
        data["status"] = self.status.value
        return data


def clamp(value: float, low: float = 0, high: float = 100) -> float:
    """Clamp ``value`` into the inclusive range ``[low, high]``."""
    return max(low, min(high, value))


def score_findings(findings: Iterable[Finding]) -> int:
    """Compute a 0-100 score from weighted findings.

    Returns 100 when there is nothing scorable (every finding is ``info``).
    """
    findings = list(findings)
    total = 0.0
    earned = 0.0
    for finding in findings:
        credit = STATUS_CREDIT.get(finding.status)
        if credit is None or finding.weight <= 0:
            continue
        total += finding.weight
        earned += finding.weight * credit
    score = 100.0 if total == 0 else 100.0 * earned / total
    if any(f.critical and f.status is Status.FAIL for f in findings):
        score = min(score, CRITICAL_CAP)
    return round(clamp(score))


def score_from_penalty(penalty: float) -> int:
    """Convert an accumulated penalty (0 = clean) into a 0-100 score."""
    return round(clamp(100 - penalty))


def grade(score: float) -> str:
    """Map a 0-100 score to a letter grade A through F."""
    for minimum, letter in GRADE_THRESHOLDS:
        if score >= minimum:
            return letter
    return "F"


def worst_status(findings: Iterable[Finding]) -> Status:
    """Return the most severe status among ``findings`` (``PASS`` when empty or all info)."""
    order = {Status.FAIL: 3, Status.WARN: 2, Status.PASS: 1, Status.INFO: 0}
    worst = Status.PASS
    for finding in findings:
        if order[finding.status] > order[worst]:
            worst = finding.status
    return worst


def count_by_status(findings: Iterable[Finding]) -> dict[str, int]:
    """Count findings per status value, including zero counts for every status."""
    counts = {status.value: 0 for status in Status}
    for finding in findings:
        counts[finding.status.value] += 1
    return counts
