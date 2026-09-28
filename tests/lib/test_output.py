import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import pytest

from deliv.lib.output import envelope, plural, render_findings, table, to_json, unstyle


class Color(Enum):
    RED = "red"


@dataclass
class Point:
    x: int


def test_envelope_has_standard_fields():
    result = envelope("dns-audit", "example.com", score=90)
    assert result["tool"] == "dns-audit"
    assert result["target"] == "example.com"
    assert result["score"] == 90
    assert "deliv_version" in result
    assert result["generated_at"].endswith("+00:00")


def test_to_json_handles_rich_types():
    data = json.loads(to_json({"c": Color.RED, "p": Point(1), "path": Path("a"), "s": {2, 1}}))
    assert data == {"c": "red", "p": {"x": 1}, "path": "a", "s": [1, 2]}
    with pytest.raises(TypeError):
        to_json({"x": object()})


def test_render_findings_adds_fix_only_for_non_pass():
    lines = render_findings(
        [
            {"check": "SPF", "status": "pass", "message": "ok", "remediation": "never shown"},
            {"check": "DMARC", "status": "warn", "message": "p=none", "remediation": "tighten"},
        ]
    )
    text = unstyle("\n".join(lines))
    assert "never shown" not in text
    assert "fix: tighten" in text
    assert "PASS" in text and "WARN" in text


def test_table_aligns_columns():
    text = table(["Day", "Volume"], [[1, 50], [10, 12000]])
    lines = text.splitlines()
    assert lines[0].startswith("Day  Volume")
    assert lines[3].startswith("10   12000")


def test_plural():
    assert plural(1, "check") == "1 check"
    assert plural(2, "check") == "2 checks"
