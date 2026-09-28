import json
from itertools import pairwise

import pytest
from typer.testing import CliRunner

from deliv import warmup_plan as wp
from deliv.cli import app
from deliv.lib.output import unstyle

runner = CliRunner()


def volumes(result):
    return [d["volume"] for d in result["plan"]]


@pytest.mark.parametrize("esp", list(wp.ESP))
def test_never_exceeds_provider_growth(esp):
    result = wp.make_plan(esp, 50, 250_000, 30)
    profile = wp.PROFILES[esp]
    vols = volumes(result)
    assert vols[0] <= profile.first_day_max
    for previous, current in pairwise(vols):
        assert current >= previous
        assert current <= previous * profile.max_daily_growth + 1e-9
    assert vols[-1] == 250_000


def test_reachable_plan_uses_requested_days():
    result = wp.make_plan("gmail", 50, 50_000, 30)
    assert len(result["plan"]) == 30
    assert volumes(result)[-1] == 50_000
    assert not result["meta"]["extended"]
    assert result["findings"][0]["status"] == "pass"


def test_too_fast_plan_is_extended_with_warning():
    result = wp.make_plan("outlook", 100, 200_000, 14)
    assert result["meta"]["extended"]
    assert len(result["plan"]) > 14
    checks = {f["check"]: f for f in result["findings"]}
    assert checks["Ramp length"]["status"] == "warn"
    assert "30%" in checks["Ramp length"]["message"]


def test_large_start_is_clamped():
    result = wp.make_plan("gmail", 5_000, 50_000, 30)
    assert volumes(result)[0] == wp.PROFILES[wp.ESP.gmail].first_day_max
    assert any(f["check"] == "Starting volume" for f in result["findings"])


def test_target_below_start_is_one_day():
    result = wp.make_plan("yahoo", 100, 80, 10)
    assert volumes(result) == [80]
    assert "no ramp needed" in result["findings"][0]["message"]


def test_unreachable_target_within_max_days(monkeypatch):
    monkeypatch.setattr(wp, "MAX_PLAN_DAYS", 10)
    result = wp.make_plan("outlook", 100, 100_000, 10)
    assert len(result["plan"]) == 10
    assert any(f["check"] == "Target volume" for f in result["findings"])


def test_audience_widens_over_time():
    plan = wp.make_plan("generic", 50, 20_000, 20)["plan"]
    assert plan[0]["audience"] == "Engaged in the last 30 days"
    assert plan[-1]["audience"] == "Engaged in the last 180 days"


def test_nice_rounding():
    assert wp.nice_round(63) == 65
    assert wp.nice_round(1234) == 1250
    assert wp.nice_round(123_456) == 123_000
    assert wp.nice_floor(1299) == 1250


def test_invalid_input():
    with pytest.raises(ValueError):
        wp.make_plan("gmail", 0, 100, 10)


def test_disclaimer_is_always_present():
    result = wp.make_plan("gmail", 50, 1_000, 10)
    assert "not a guarantee of inbox placement" in result["disclaimer"]


def test_cli():
    args = ["warmup-plan", "--esp", "gmail", "--start-volume", "50", "--target-volume", "20000",
            "--days", "21"]  # fmt: skip
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    text = unstyle(result.output)
    assert "Planning guidance, not a guarantee of inbox placement" in text
    assert "Day" in text and "Send to" in text and "Daily gate" in text
    data = json.loads(runner.invoke(app, [*args, "--json"]).output)
    assert data["tool"] == "warmup-plan" and len(data["plan"]) == 21
    assert runner.invoke(app, ["warmup-plan", "--target-volume", "100", "--esp", "aol"]).exit_code


def test_cli_requires_target():
    assert runner.invoke(app, ["warmup-plan"]).exit_code != 0
