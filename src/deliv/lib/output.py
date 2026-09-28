"""Shared human-readable and JSON output formatting.

Every tool builds a plain ``dict`` result with :func:`envelope`, then calls :func:`emit`. With
``--json`` the dict is printed as JSON (the same shape ``deliv report`` consumes). Without it, the
tool's own renderer turns the dict into terminal text using the helpers below, so every command
looks and reads the same way.
"""

import json
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import typer

from deliv import __version__

_STATUS_COLORS = {
    "pass": typer.colors.GREEN,
    "warn": typer.colors.YELLOW,
    "fail": typer.colors.RED,
    "info": typer.colors.BLUE,
}

_GRADE_COLORS = {
    "A": typer.colors.GREEN,
    "B": typer.colors.GREEN,
    "C": typer.colors.YELLOW,
    "D": typer.colors.YELLOW,
    "F": typer.colors.RED,
}


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def unstyle(text: str) -> str:
    """Remove ANSI color codes from ``text``."""
    return _ANSI_RE.sub("", text)


def envelope(tool: str, target: str, **fields: Any) -> dict[str, Any]:
    """Build the standard result dict shared by every tool.

    Args:
        tool: The subcommand name (for example ``"dns-audit"``).
        target: What was checked: a domain, IP, file name, or input summary.
        **fields: Tool-specific fields (``score``, ``grade``, ``findings``, and so on).
    """
    result: dict[str, Any] = {
        "tool": tool,
        "target": target,
        "deliv_version": __version__,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    }
    result.update(fields)
    return result


def _json_default(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def to_json(data: Any) -> str:
    """Serialize ``data`` to indented JSON, handling enums, dataclasses, paths, and sets."""
    return json.dumps(data, indent=2, default=_json_default, ensure_ascii=False)


def emit(result: Any, as_json: bool, render: Callable[[Any], str]) -> None:
    """Print ``result`` as JSON or through ``render`` for humans."""
    typer.echo(to_json(result) if as_json else render(result))


def status_label(status: str) -> str:
    """Return a colored, fixed-width status label such as ``PASS`` or ``FAIL``."""
    status = status.lower()
    return typer.style(status.upper().ljust(4), fg=_STATUS_COLORS.get(status), bold=True)


def grade_badge(grade: str, score: int | float | None = None) -> str:
    """Return a colored ``Grade B (84/100)`` style badge."""
    text = f"Grade {grade}" if score is None else f"Grade {grade} ({round(score)}/100)"
    return typer.style(text, fg=_GRADE_COLORS.get(grade, typer.colors.WHITE), bold=True)


def heading(text: str) -> str:
    """Return a bold heading followed by an underline of matching length."""
    return f"{typer.style(text, bold=True)}\n{'=' * len(text)}"


def subheading(text: str) -> str:
    """Return a bold section label."""
    return typer.style(text, bold=True)


def render_findings(findings: Iterable[dict[str, Any]], indent: str = "") -> list[str]:
    """Render finding dicts as aligned status lines with ``fix:`` hints under non-pass items."""
    findings = list(findings)
    width = max((len(f.get("check", "")) for f in findings), default=0)
    lines: list[str] = []
    for finding in findings:
        check = finding.get("check", "")
        lines.append(
            f"{indent}{status_label(finding['status'])}  {check.ljust(width)}  {finding['message']}"
        )
        remediation = finding.get("remediation")
        if remediation and finding["status"] != "pass":
            lines.append(f"{indent}      {' ' * width}  fix: {remediation}")
    return lines


def table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    """Render a simple left-aligned text table with a header separator."""
    str_rows = [[str(cell) for cell in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in str_rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    lines = [
        "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)).rstrip(),
        "  ".join("-" * w for w in widths),
    ]
    lines.extend(
        "  ".join(c.ljust(widths[i]) for i, c in enumerate(row)).rstrip() for row in str_rows
    )
    return "\n".join(lines)


def plural(count: int, noun: str, suffix: str = "s") -> str:
    """Return ``"1 check"`` / ``"3 checks"`` style text."""
    return f"{count} {noun}{'' if count == 1 else suffix}"
