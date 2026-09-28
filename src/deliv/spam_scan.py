"""``deliv spam-scan``: score email copy for spam-filter risk.

Matches the curated phrases in ``spam_triggers.json`` (case-insensitive, on word boundaries) plus a
handful of formatting patterns (shouting, ``!!!``, ``$$$``). Each hit costs its weight; the score is
100 minus the total, graded A-F, with a per-category breakdown and suggested rewrites for the three
heaviest hits.
"""

import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Annotated, Any

import typer

from deliv.lib.content import EmailContent, load_content
from deliv.lib.options import JsonFlag
from deliv.lib.output import emit, envelope, grade_badge, heading, subheading, table
from deliv.lib.scoring import Finding, Status, grade, score_from_penalty

#: Subject-line hits cost this much more than body hits: filters weigh subjects heavily.
SUBJECT_MULTIPLIER = 1.5
#: Repeats of one phrase add 25% of its weight each, up to this multiple of the weight.
MAX_REPEAT_MULTIPLE = 2.0
#: A category whose penalty reaches this is reported as a failure rather than a warning.
CATEGORY_FAIL_PENALTY = 15.0

#: Formatting pattern id -> (regex, per-message cap on counted hits).
_PATTERNS: dict[str, tuple[re.Pattern[str], int]] = {
    "shouting_words": (re.compile(r"\b[A-Z]{4,}\b"), 5),
    "exclamation_runs": (re.compile(r"!{2,}"), 4),
    "question_exclamation": (re.compile(r"(?:\?+!+|!+\?+)[?!]*"), 3),
    "dollar_runs": (re.compile(r"\${2,}"), 3),
    "percent_off_stack": (re.compile(r"\b\d{1,2}\s?%\s?off\b", re.IGNORECASE), 0),
}
#: Shouted words that are normal in email copy and should not count as shouting.
_ALLOWED_CAPS = frozenset(
    {"HTML", "HTTP", "HTTPS", "FAQS", "USPS", "UPS", "SMTP", "NASA", "ASAP", "RSVP", "PDF", "SALE"}
)


@dataclass(frozen=True)
class Trigger:
    """One curated trigger phrase."""

    phrase: str
    category: str
    weight: float
    rewrite: str


@dataclass
class TriggerSet:
    """The loaded dataset: phrases, formatting pattern weights, and category descriptions."""

    triggers: list[Trigger]
    patterns: dict[str, dict[str, Any]]
    categories: dict[str, str]


@dataclass
class Match:
    """One trigger hit in the scanned content."""

    phrase: str
    category: str
    weight: float
    line: int
    field: str
    text: str
    rewrite: str
    start: int = 0
    end: int = 0


def default_triggers_path() -> Path:
    """Locate ``spam_triggers.json``: the packaged copy first, then the repo's ``data/`` folder."""
    packaged = resources.files("deliv").joinpath("data/spam_triggers.json")
    if packaged.is_file():
        return Path(str(packaged))
    return Path(__file__).resolve().parents[2] / "data" / "spam_triggers.json"


def load_triggers(path: str | Path | None = None) -> TriggerSet:
    """Load and validate a trigger dataset (the bundled one when ``path`` is None)."""
    if path is None:
        return _load_default_triggers()
    return _parse_triggers(json.loads(Path(path).read_text(encoding="utf-8")))


@lru_cache(maxsize=1)
def _load_default_triggers() -> TriggerSet:
    return _parse_triggers(json.loads(default_triggers_path().read_text(encoding="utf-8")))


def _parse_triggers(data: dict[str, Any]) -> TriggerSet:
    triggers: list[Trigger] = []
    patterns: dict[str, dict[str, Any]] = {}
    categories: dict[str, str] = {}
    for name, category in data.get("categories", {}).items():
        categories[name] = category.get("description", "")
        for item in category.get("phrases", []):
            weight = float(item["weight"])
            if not 0 < weight <= 10:
                raise ValueError(f"weight for '{item['phrase']}' must be between 0 and 10")
            triggers.append(Trigger(item["phrase"], name, weight, item.get("rewrite", "")))
        for pattern_id, spec in category.get("patterns", {}).items():
            patterns[pattern_id] = {**spec, "category": name}
    return TriggerSet(triggers, patterns, categories)


@lru_cache(maxsize=2048)
def phrase_regex(phrase: str) -> re.Pattern[str]:
    """Compile a case-insensitive, word-boundary regex for ``phrase``.

    Boundaries are applied only where the phrase starts or ends with a word character, so
    ``"earn $"`` still matches ``"earn $500"``. Internal whitespace matches any whitespace run.
    """
    body = r"\s+".join(re.escape(word) for word in phrase.split())
    prefix = r"(?<!\w)" if re.match(r"\w", phrase) else ""
    suffix = r"(?!\w)" if re.search(r"\w$", phrase) else ""
    return re.compile(prefix + body + suffix, re.IGNORECASE)


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def find_phrase_matches(text: str, triggers: list[Trigger], field: str = "body") -> list[Match]:
    """Find every trigger phrase in ``text``, keeping the heavier phrase where two overlap."""
    candidates: list[Match] = []
    for trigger in triggers:
        for hit in phrase_regex(trigger.phrase).finditer(text):
            candidates.append(
                Match(
                    trigger.phrase,
                    trigger.category,
                    trigger.weight,
                    _line_of(text, hit.start()),
                    field,
                    hit.group(0),
                    trigger.rewrite,
                    hit.start(),
                    hit.end(),
                )
            )
    candidates.sort(key=lambda m: (-m.weight, -(m.end - m.start), m.start))
    kept: list[Match] = []
    for match in candidates:
        if all(match.end <= k.start or match.start >= k.end for k in kept):
            kept.append(match)
    return sorted(kept, key=lambda m: (m.start, m.phrase))


def find_pattern_matches(
    text: str, patterns: dict[str, dict[str, Any]], field: str = "body"
) -> list[Match]:
    """Evaluate the formatting pattern checks against ``text``."""
    matches: list[Match] = []
    for pattern_id, spec in patterns.items():
        if pattern_id not in _PATTERNS:
            continue
        regex, cap = _PATTERNS[pattern_id]
        hits = [h for h in regex.finditer(text) if h.group(0) not in _ALLOWED_CAPS]
        if pattern_id == "percent_off_stack":
            hits = hits[2:3]  # one hit, and only when three or more offers are stacked
        elif cap:
            hits = hits[:cap]
        for hit in hits:
            matches.append(
                Match(
                    pattern_id,
                    spec["category"],
                    float(spec["weight"]),
                    _line_of(text, hit.start()),
                    field,
                    hit.group(0),
                    spec.get("rewrite", ""),
                    hit.start(),
                    hit.end(),
                )
            )
    return matches


def _penalties(matches: list[Match]) -> dict[str, float]:
    """Return the penalty per category, applying repeat and subject multipliers."""
    per_phrase: dict[tuple[str, str], list[Match]] = {}
    for match in matches:
        per_phrase.setdefault((match.category, match.phrase), []).append(match)
    totals: Counter[str] = Counter()
    for (category, _), hits in per_phrase.items():
        if category == "formatting":
            totals[category] += sum(h.weight for h in hits)
            continue
        weight = hits[0].weight
        multiple = min(MAX_REPEAT_MULTIPLE, 1 + 0.25 * (len(hits) - 1))
        if any(h.field == "subject" for h in hits):
            multiple *= SUBJECT_MULTIPLIER
        totals[category] += weight * multiple
    return dict(totals)


def top_rewrites(matches: list[Match], limit: int = 3) -> list[dict[str, Any]]:
    """Return rewrite suggestions for the ``limit`` highest-weight distinct phrases."""
    seen: dict[str, Match] = {}
    for match in sorted(matches, key=lambda m: (-m.weight, m.line)):
        seen.setdefault(match.phrase, match)
    return [
        {
            "phrase": m.phrase,
            "found": m.text,
            "category": m.category,
            "weight": m.weight,
            "line": m.line,
            "field": m.field,
            "rewrite": m.rewrite,
        }
        for m in list(seen.values())[:limit]
    ]


def scan_content(content: EmailContent, triggers: TriggerSet | None = None) -> dict[str, Any]:
    """Scan loaded content and return the graded spam-scan result dict."""
    triggers = triggers or load_triggers()
    matches = find_phrase_matches(content.text, triggers.triggers)
    matches += find_pattern_matches(content.text, triggers.patterns)
    if content.subject:
        matches += find_phrase_matches(content.subject, triggers.triggers, field="subject")
        matches += find_pattern_matches(content.subject, triggers.patterns, field="subject")
    penalties = _penalties(matches)
    score = score_from_penalty(sum(penalties.values()))

    breakdown: dict[str, dict[str, Any]] = {}
    for category in [*triggers.categories, *penalties]:
        if category in breakdown:
            continue
        hits = [m for m in matches if m.category == category]
        breakdown[category] = {
            "matches": len(hits),
            "penalty": round(penalties.get(category, 0.0), 2),
        }

    findings = _category_findings(breakdown, matches, triggers)
    categories_hit = sum(1 for c in breakdown.values() if c["matches"])
    return envelope(
        "spam-scan",
        content.source,
        input_format=content.source_format,
        is_html=content.is_html,
        score=score,
        grade=grade(score),
        summary=(
            f"{len(matches)} trigger match{'es' if len(matches) != 1 else ''} across "
            f"{categories_hit} categor{'ies' if categories_hit != 1 else 'y'}."
        ),
        categories=breakdown,
        matches=[
            {k: v for k, v in asdict(m).items() if k not in {"start", "end"}}
            for m in sorted(matches, key=lambda m: (m.field != "subject", m.line, m.phrase))
        ],
        rewrites=top_rewrites([m for m in matches if m.category != "formatting"])
        or top_rewrites(matches),
        findings=[f.to_dict() for f in findings],
    )


def _category_findings(
    breakdown: dict[str, dict[str, Any]], matches: list[Match], triggers: TriggerSet
) -> list[Finding]:
    findings: list[Finding] = []
    for category, stats in breakdown.items():
        hits = sorted(
            (m for m in matches if m.category == category), key=lambda m: (-m.weight, m.line)
        )
        if not hits:
            findings.append(
                Finding(f"Spam triggers: {category}", Status.PASS, "No matches.", None, category)
            )
            continue
        status = Status.FAIL if stats["penalty"] >= CATEGORY_FAIL_PENALTY else Status.WARN
        phrases = ", ".join(dict.fromkeys(f'"{m.text}"' for m in hits[:4]))
        findings.append(
            Finding(
                f"Spam triggers: {category}",
                status,
                f"{len(hits)} match{'es' if len(hits) != 1 else ''} ({phrases}), "
                f"costing {stats['penalty']:g} points.",
                hits[0].rewrite or triggers.categories.get(category) or None,
                category,
                details={"penalty": stats["penalty"]},
            )
        )
    return findings


def scan_file(path: str | Path, triggers_path: str | Path | None = None) -> dict[str, Any]:
    """Load ``path`` (text, HTML, ``.eml``, or ``-`` for stdin) and scan it."""
    return scan_content(load_content(path), load_triggers(triggers_path))


def render(result: dict[str, Any]) -> str:
    """Render a spam-scan result for the terminal."""
    kind = {"html": "HTML input", "eml": "email message", "text": "plain text"}
    lines = [
        heading(f"Spam-risk scan: {result['target']} ({kind.get(result['input_format'], '')})"),
        f"{grade_badge(result['grade'], result['score'])}   {result['summary']}",
        "",
        subheading("Category breakdown"),
        table(
            ["Category", "Matches", "Points lost"],
            [
                [name, stats["matches"], f"-{stats['penalty']:g}" if stats["penalty"] else "0"]
                for name, stats in result["categories"].items()
            ],
        ),
    ]
    if result["matches"]:
        lines += [
            "",
            subheading("Matches"),
            table(
                ["Where", "Found", "Category", "Weight"],
                [
                    [
                        "subject" if m["field"] == "subject" else f"line {m['line']}",
                        m["text"] if len(m["text"]) <= 40 else m["text"][:37] + "...",
                        m["category"],
                        f"{m['weight']:g}",
                    ]
                    for m in result["matches"]
                ],
            ),
        ]
    if result["rewrites"]:
        lines += ["", subheading("Suggested rewrites (highest weight first)")]
        for index, item in enumerate(result["rewrites"], start=1):
            where = "subject" if item["field"] == "subject" else f"line {item['line']}"
            lines.append(f'  {index}. "{item["found"]}" ({where}): {item["rewrite"]}')
    return "\n".join(lines)


def command(
    file: Annotated[
        str,
        typer.Argument(
            help="The email to scan: a .txt, .html, or .eml file, or '-' to read from stdin."
        ),
    ],
    triggers: Annotated[
        Path | None,
        typer.Option(
            "--triggers",
            help="Use your own trigger list (same JSON format as data/spam_triggers.json).",
            exists=True,
            dir_okay=False,
        ),
    ] = None,
    as_json: JsonFlag = False,
) -> None:
    """Score email copy for spam-filter risk (0-100, graded A-F).

    Flags pressure, money, freebie, health, adult, and phishing-style phrases plus shouty
    formatting, shows the line each one is on, and suggests rewrites for the worst three.
    """
    if file != "-" and not Path(file).is_file():
        raise typer.BadParameter(f"File not found: {file}", param_hint="FILE")
    emit(scan_file(file, triggers), as_json, render)
