"""``deliv report``: combine saved ``--json`` outputs into one shareable deliverability report.

Reads one or more JSON files (each holding a single tool result or an array of them), then builds
an executive summary with grades, a prioritized fix list (blocking issues first, DNS and reputation
before content), and a section per tool. Renders Markdown or a single self-contained HTML file.
"""

import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from statistics import mean
from typing import Annotated, Any

import typer

from deliv import __version__
from deliv.lib.output import to_json
from deliv.lib.scoring import grade

#: Section order, and the order fixes are prioritized within the same severity.
TOOL_ORDER: tuple[str, ...] = (
    "dns-audit",
    "blacklist",
    "header-analyze",
    "copy-check",
    "spam-scan",
    "bounce-classify",
    "warmup-plan",
)

TOOL_TITLES: dict[str, str] = {
    "dns-audit": "DNS authentication audit",
    "blacklist": "Blocklist check",
    "header-analyze": "Header analysis",
    "copy-check": "Pre-send QA",
    "spam-scan": "Spam-risk scan",
    "bounce-classify": "Bounce classification",
    "warmup-plan": "Warmup plan",
}

_SEVERITY = {"fail": 0, "warn": 1}
_PRIORITY_LABEL = {"fail": "P1", "warn": "P2"}


class ReportFormat(str, Enum):
    """Output formats for ``deliv report``."""

    md = "md"
    html = "html"


class ReportInputError(ValueError):
    """The report input is missing, not JSON, or holds no deliv results."""


def load_results(paths: list[Path]) -> tuple[list[dict[str, Any]], list[str]]:
    """Load tool results from JSON files.

    Each file may hold one result object, an array of results, or ``{"results": [...]}``.
    Returns the results plus warnings about anything skipped.
    """
    results: list[dict[str, Any]] = []
    warnings: list[str] = []
    for path in paths:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ReportInputError(f"input file not found: {path}") from exc
        except json.JSONDecodeError as exc:
            raise ReportInputError(
                f"{path} is not valid JSON: {exc.msg} (line {exc.lineno})"
            ) from exc
        if isinstance(data, dict) and "tool" not in data and isinstance(data.get("results"), list):
            data = data["results"]
        items = data if isinstance(data, list) else [data]
        for index, item in enumerate(items):
            if isinstance(item, dict) and item.get("tool") in TOOL_TITLES:
                results.append(item)
            else:
                warnings.append(f"skipped item {index} in {path}: not a deliv tool result")
    if not results:
        raise ReportInputError("no deliv results found; save tool output with --json first")
    return results, warnings


def result_label(result: dict[str, Any]) -> str:
    """One short label for a tool result: its grade, verdict, or classification."""
    if "grade" in result and "score" in result:
        label = f"{result['grade']} ({result['score']}/100)"
        if result.get("verdict"):
            label += f", {result['verdict']}"
        return label
    if result.get("verdict"):
        return str(result["verdict"])
    if result["tool"] == "bounce-classify":
        if "results" in result:
            return f"{len(result['results'])} bounces"
        return f"{result.get('classification', 'unknown')} / {result.get('action', '-')}"
    if result["tool"] == "warmup-plan":
        return f"{len(result.get('plan', []))} days"
    return "-"


def _status_of(result: dict[str, Any]) -> str:
    statuses = {f.get("status") for f in result.get("findings", [])}
    for status in ("fail", "warn", "pass"):
        if status in statuses:
            return status
    return "info"


def build_report(results: list[dict[str, Any]], title: str | None = None) -> dict[str, Any]:
    """Aggregate tool results into the report model used by both renderers."""
    order = {tool: index for index, tool in enumerate(TOOL_ORDER)}
    sections = sorted(
        enumerate(results), key=lambda pair: (order.get(pair[1]["tool"], 99), pair[0])
    )
    sections_out = [item for _, item in sections]

    fixes: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for position, result in enumerate(sections_out):
        for finding in result.get("findings", []):
            status = finding.get("status")
            if status not in _SEVERITY:
                continue
            key = (result["tool"], finding.get("check", ""), finding.get("remediation") or "")
            if key in seen:
                continue
            seen.add(key)
            fixes.append(
                {
                    "priority": _PRIORITY_LABEL[status],
                    "status": status,
                    "tool": result["tool"],
                    "tool_title": TOOL_TITLES[result["tool"]],
                    "target": result.get("target", ""),
                    "check": finding.get("check", ""),
                    "problem": finding.get("message", ""),
                    "fix": finding.get("remediation") or "Review this finding.",
                    "_sort": (
                        _SEVERITY[status],
                        -float(finding.get("weight", 1) or 0) if status == "fail" else 0,
                        position,
                    ),
                }
            )
    fixes.sort(key=lambda fix: fix["_sort"])
    for fix in fixes:
        del fix["_sort"]

    scores = [r["score"] for r in sections_out if isinstance(r.get("score"), (int, float))]
    overall_score = round(mean(scores)) if scores else None
    targets = list(dict.fromkeys(r.get("target", "") for r in sections_out))
    return {
        "tool": "report",
        "title": title or "Email deliverability report",
        "deliv_version": __version__,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "overall_score": overall_score,
        "overall_grade": grade(overall_score) if overall_score is not None else None,
        "blocking": sum(1 for f in fixes if f["status"] == "fail"),
        "to_review": sum(1 for f in fixes if f["status"] == "warn"),
        "targets": targets,
        "summary_rows": [
            {
                "tool": r["tool"],
                "tool_title": TOOL_TITLES[r["tool"]],
                "target": r.get("target", ""),
                "result": result_label(r),
                "status": _status_of(r),
                "summary": r.get("summary", ""),
            }
            for r in sections_out
        ],
        "fixes": fixes,
        "sections": sections_out,
    }


def headline(report: dict[str, Any]) -> str:
    """One sentence summarizing the whole report."""
    parts = []
    if report["overall_grade"]:
        parts.append(
            f"Overall grade {report['overall_grade']} ({report['overall_score']}/100) across "
            f"{sum(1 for r in report['sections'] if 'score' in r)} graded checks."
        )
    parts.append(
        f"{report['blocking']} blocking issue{'s' if report['blocking'] != 1 else ''} and "
        f"{report['to_review']} item{'s' if report['to_review'] != 1 else ''} to review."
    )
    return " ".join(parts)


# --------------------------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------------------------


def _md_cell(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


def _md_table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(" --- " for _ in headers) + "|"]
    lines += ["| " + " | ".join(_md_cell(c) for c in row) + " |" for row in rows]
    return lines


def _md_extras(result: dict[str, Any]) -> list[str]:
    tool = result["tool"]
    lines: list[str] = []
    if tool in {"spam-scan", "copy-check"} and result.get("rewrites"):
        lines += ["", "**Suggested rewrites**", ""]
        lines += [
            f'{i}. "{_md_cell(r["found"])}" ({r["field"]}, line {r["line"]}): '
            f"{_md_cell(r['rewrite'])}"
            for i, r in enumerate(result["rewrites"], 1)
        ]
    if tool == "header-analyze":
        alignment = result.get("alignment", {})
        lines += [
            "",
            f"- Sending IP: {result.get('sending_ip') or 'unknown'}",
            f"- From domain: {alignment.get('from_domain')}; envelope-from: "
            f"{alignment.get('envelope_from_domain')}; alignment: {alignment.get('verdict')}",
            f"- Diagnosis: {result.get('diagnosis', '')}",
        ]
    if tool == "bounce-classify":
        rows = result.get("results") or [result]
        lines += ["", *_md_table(
            ["Class", "Action", "Code", "Rule"],
            [
                [r.get("classification"), r.get("action"),
                 r.get("status_code") or r.get("smtp_code") or "-", r.get("rule", {}).get("id")]
                for r in rows
            ],
        )]  # fmt: skip
    if tool == "warmup-plan" and result.get("plan"):
        lines += ["", f"_{result.get('disclaimer', '')}_", ""]
        lines += _md_table(
            ["Day", "Volume", "Send to"],
            [[d["day"], f"{d['volume']:,}", d["audience"]] for d in result["plan"]],
        )
    return lines


def render_markdown(report: dict[str, Any]) -> str:
    """Render the report as GitHub-flavored Markdown."""
    lines = [
        f"# {report['title']}",
        "",
        f"Generated {report['generated_at']} by deliv {report['deliv_version']}.",
        "",
        "## Executive summary",
        "",
        f"**{headline(report)}**",
        "",
    ]
    lines += _md_table(
        ["Check", "Target", "Result", "Summary"],
        [[r["tool_title"], r["target"], r["result"], r["summary"]] for r in report["summary_rows"]],
    )
    lines += ["", "## Prioritized fix list", ""]
    if report["fixes"]:
        for index, fix in enumerate(report["fixes"], 1):
            lines.append(
                f"{index}. **{fix['priority']} {_md_cell(fix['check'])}** "
                f"({fix['tool_title']}, {_md_cell(fix['target'])}): {_md_cell(fix['problem'])} "
                f"Fix: {_md_cell(fix['fix'])}"
            )
    else:
        lines.append("Nothing to fix. Every check passed.")
    for result in report["sections"]:
        lines += [
            "",
            f"## {TOOL_TITLES[result['tool']]}: {_md_cell(result.get('target', ''))}",
            "",
            f"**{result_label(result)}.** {_md_cell(result.get('summary', ''))}",
            "",
        ]
        findings = result.get("findings", [])
        if findings:
            lines += _md_table(
                ["Status", "Check", "Finding", "Fix"],
                [
                    [f["status"].upper(), f.get("check", ""), f.get("message", ""),
                     f.get("remediation") if f["status"] != "pass" else ""]
                    for f in findings
                ],
            )  # fmt: skip
        lines += _md_extras(result)
    lines += [
        "",
        "---",
        "",
        "Findings are automated checks and heuristics. Grades describe configuration and content "
        "risk; they do not guarantee inbox placement.",
        "",
    ]
    return "\n".join(lines)


def render_html(report: dict[str, Any]) -> str:
    """Render the report as one self-contained HTML file (inline CSS, no external assets)."""
    from deliv.report_html import render_html_document

    return render_html_document(report)


def command(
    input_files: Annotated[
        list[Path],
        typer.Option(
            "--input",
            "-i",
            help="JSON saved from other deliv commands with --json: one result or an array. "
            "Repeat for several files.",
            dir_okay=False,
        ),
    ],
    fmt: Annotated[
        ReportFormat, typer.Option("--format", "-f", help="md (Markdown) or html (single file).")
    ] = ReportFormat.md,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the report here instead of printing it."),
    ] = None,
    title: Annotated[
        str | None,
        typer.Option("--title", help="Report title (default: Email deliverability report)."),
    ] = None,
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Print the aggregated report data as JSON instead."),
    ] = False,
) -> None:
    """Turn saved --json results into one shareable report: grades, fix list, details.

    Example: deliv dns-audit example.com --json > dns.json, then
    deliv report --input dns.json --format html --output report.html
    """
    try:
        results, warnings = load_results(input_files)
    except ReportInputError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(2) from exc
    for warning in warnings:
        typer.echo(f"Warning: {warning}", err=True)
    report = build_report(results, title)
    if as_json:
        typer.echo(to_json(report))
        return
    text = render_html(report) if fmt is ReportFormat.html else render_markdown(report)
    if output:
        output.write_text(text, encoding="utf-8")
        typer.echo(f"Wrote {fmt.value.upper()} report to {output}", err=True)
    else:
        typer.echo(text)
