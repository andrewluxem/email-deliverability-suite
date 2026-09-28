import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from deliv import spam_scan
from deliv.cli import app
from deliv.lib.content import from_string
from deliv.lib.output import unstyle

FIXTURES = Path(__file__).parent / "fixtures"
DATA = Path(__file__).resolve().parents[1] / "data" / "spam_triggers.json"
runner = CliRunner()


def scan(text, subject=None):
    content = from_string(text)
    content.subject = subject
    return spam_scan.scan_content(content)


def test_dataset_is_curated_and_large_enough():
    data = json.loads(DATA.read_text())
    categories = data["categories"]
    assert {"urgency", "money", "free", "health", "adult", "formatting", "shady"} <= set(categories)
    phrases = [p for c in categories.values() for p in c["phrases"]]
    assert len(phrases) >= 150
    lowered = [p["phrase"].lower() for p in phrases]
    assert len(lowered) == len(set(lowered)), "duplicate phrases"
    for category in categories.values():
        assert category["description"]
    for phrase in phrases:
        assert 1 <= phrase["weight"] <= 10
        assert phrase["rewrite"]
        assert phrase["phrase"] == phrase["phrase"].strip()
    assert categories["formatting"]["phrases"] == []
    assert set(categories["formatting"]["patterns"]) == set(spam_scan._PATTERNS)


def test_default_triggers_path_exists():
    assert spam_scan.default_triggers_path().is_file()


def test_word_boundaries_and_case():
    triggers = spam_scan.load_triggers().triggers
    assert spam_scan.find_phrase_matches("ACT NOW before Friday", triggers)[0].phrase == "act now"
    assert not spam_scan.find_phrase_matches("the curenet project", triggers)
    assert not spam_scan.find_phrase_matches("reinheritance", triggers)


def test_phrases_match_across_line_breaks():
    triggers = spam_scan.load_triggers().triggers
    (match,) = spam_scan.find_phrase_matches("please\nact\n  now", triggers)
    assert match.line == 2


def test_trailing_symbol_phrase_matches_amounts():
    triggers = spam_scan.load_triggers().triggers
    assert any(
        m.phrase == "earn $" for m in spam_scan.find_phrase_matches("Earn $500 today", triggers)
    )


def test_overlapping_matches_keep_heavier_phrase():
    triggers = spam_scan.load_triggers().triggers
    phrases = [m.phrase for m in spam_scan.find_phrase_matches("Make money fast", triggers)]
    assert phrases == ["make money fast"]


def test_clean_copy_scores_high():
    result = spam_scan.scan_file(FIXTURES / "newsletter_clean.html")
    assert result["grade"] == "A"
    assert result["is_html"] is True
    assert result["input_format"] == "html"


def test_spammy_copy_scores_low_with_breakdown():
    result = spam_scan.scan_file(FIXTURES / "promo_spammy.html")
    assert result["grade"] == "F"
    assert result["categories"]["urgency"]["matches"] >= 2
    assert result["categories"]["formatting"]["matches"] >= 2
    lines = {m["phrase"]: m["line"] for m in result["matches"]}
    assert lines["act now"] == 1
    assert len(result["rewrites"]) == 3
    weights = [r["weight"] for r in result["rewrites"]]
    assert weights == sorted(weights, reverse=True)
    failing = [f for f in result["findings"] if f["status"] == "fail"]
    assert failing and all(f["remediation"] for f in failing)


def test_repeats_have_diminishing_cost():
    once = scan("Act now.")["score"]
    thrice = scan("Act now. Act now. Act now.")["score"]
    many = scan(" ".join(["Act now."] * 10))["score"]
    assert once > thrice > many
    assert 100 - many == 2 * (100 - once)


def test_subject_hits_cost_more():
    body_only = scan("Act now")["score"]
    subject_only = scan("Hello", subject="Act now")["score"]
    assert subject_only < body_only
    assert scan("Hello", subject="Act now")["matches"][0]["field"] == "subject"


@pytest.mark.parametrize(
    ("text", "pattern"),
    [
        ("WOW AMAZING DEALS", "shouting_words"),
        ("Hello!!", "exclamation_runs"),
        ("Really?!", "question_exclamation"),
        ("Cash $$$", "dollar_runs"),
        ("10% off shoes, 20% off hats, 30% off bags", "percent_off_stack"),
    ],
)
def test_formatting_patterns(text, pattern):
    assert pattern in {m["phrase"] for m in scan(text)["matches"]}


def test_allowed_acronyms_are_not_shouting():
    assert scan("Download the PDF over HTTPS")["matches"] == []


def test_custom_trigger_file(tmp_path):
    custom = tmp_path / "t.json"
    custom.write_text(
        json.dumps(
            {
                "categories": {
                    "brand": {
                        "description": "d",
                        "phrases": [{"phrase": "megadeal", "weight": 10, "rewrite": "Say 'sale'."}],
                    }
                }
            }
        )
    )
    result = spam_scan.scan_file(_write(tmp_path, "Our MEGADEAL is live"), custom)
    assert result["score"] == 90
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"categories": {"x": {"phrases": [{"phrase": "a", "weight": 50}]}}}))
    with pytest.raises(ValueError):
        spam_scan.load_triggers(bad)


def _write(tmp_path, text):
    path = tmp_path / "copy.txt"
    path.write_text(text)
    return path


def test_cli_human_and_json(tmp_path):
    result = runner.invoke(app, ["spam-scan", str(FIXTURES / "promo_spammy.html")])
    assert result.exit_code == 0, result.output
    text = unstyle(result.output)
    assert "HTML input" in text and "Suggested rewrites" in text and "line 1" in text
    result = runner.invoke(app, ["spam-scan", str(FIXTURES / "promo_spammy.html"), "--json"])
    data = json.loads(result.output)
    assert data["tool"] == "spam-scan"
    assert "start" not in data["matches"][0]


def test_cli_reads_stdin():
    result = runner.invoke(app, ["spam-scan", "-", "--json"], input="Lose weight fast!!")
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["target"] == "-"


def test_cli_missing_file():
    result = runner.invoke(app, ["spam-scan", "nope.html"])
    assert result.exit_code != 0
