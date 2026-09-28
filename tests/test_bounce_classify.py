import json

import pytest
from typer.testing import CliRunner

from deliv import bounce_classify as bc
from deliv.cli import app
from deliv.lib.output import unstyle

runner = CliRunner()


@pytest.mark.parametrize(
    ("text", "classification", "action", "rule"),
    [
        # bare codes
        ("5.1.1", "hard", "suppress", "rfc3463-5.1.1"),
        ("4.2.2", "soft", "retry", "rfc3463-4.2.2"),
        ("5.2.2", "soft", "retry", "rfc3463-5.2.2"),
        ("5.7.26", "block", "investigate", "rfc3463-5.7.26"),
        ("4.7.1", "block", "retry", "rfc3463-4.7.1"),
        ("5.1.10", "hard", "suppress", "rfc3463-5.1.10"),
        # class fallbacks
        ("5.1.99", "hard", "suppress", "rfc3463-5.1.x"),
        ("4.4.2", "soft", "retry", "rfc3463-4.4.x"),
        ("5.6.3", "block", "investigate", "rfc3463-5.6.x"),
        ("5.9.9", "hard", "suppress", "rfc3463-5.x"),
        # Gmail
        (
            "550-5.1.1 The email account that you tried to reach does not exist. Please try "
            "double-checking the recipient's email address for typos",
            "hard", "suppress", "gmail-no-such-user",
        ),
        (
            "452-4.2.2 The recipient's inbox is out of storage space. Please direct the recipient "
            "to https://support.example.com",
            "soft", "retry", "gmail-over-quota",
        ),
        (
            "421-4.7.28 Our system has detected an unusual rate of unsolicited mail originating "
            "from your IP address",
            "block", "investigate", "gmail-unsolicited",
        ),
        (
            "550-5.7.26 Unauthenticated email from example.com is not accepted due to domain's "
            "DMARC policy",
            "block", "investigate", "gmail-unauthenticated",
        ),
        (
            "450-4.2.1 The user you are trying to contact is receiving mail at a rate that "
            "prevents additional messages from being delivered",
            "soft", "retry", "gmail-rate-limited",
        ),
        # Microsoft
        (
            "550 5.7.1 Unfortunately, messages from [192.0.2.25] weren't sent. Please contact your "
            "Internet service provider since part of their network is on our block list (S3150)",
            "block", "investigate", "microsoft-blocklist",
        ),
        (
            "550 5.5.0 Requested action not taken: mailbox unavailable (S2017062302)",
            "hard", "suppress", "microsoft-mailbox-unavailable",
        ),
        (
            "451 4.7.650 The mail server [192.0.2.25] has been temporarily rate limited due to IP "
            "reputation",
            "block", "retry", "microsoft-ip-reputation",
        ),
        # Yahoo
        (
            "421 4.7.0 [TSS04] Messages from 192.0.2.25 temporarily deferred due to unexpected "
            "volume or user complaints",
            "block", "retry", "yahoo-deferred",
        ),
        (
            "553 5.7.2 [TSS09] All messages from 192.0.2.25 will be permanently deferred",
            "block", "investigate", "yahoo-permanent",
        ),
        (
            "554 delivery error: dd This user doesn't have a yahoo.com account (x@yahoo.com)",
            "hard", "suppress", "yahoo-no-account",
        ),
        # generic text, no code
        ("Recipient address rejected: User unknown in virtual mailbox table", "hard", "suppress",
         "text-user-unknown"),
        ("Mailbox full", "soft", "retry", "text-mailbox-full"),
        ("Client host rejected: listed at zen.spamhaus.org", "block", "investigate",
         "text-blocklisted"),
        ("Greylisted, please try again in 5 minutes", "soft", "retry", "text-temporary"),
        ("Message rejected due to DMARC policy", "block", "investigate", "text-auth"),
        ("Domain not found", "hard", "suppress", "text-bad-domain"),
        # temporary code overrides permanent-sounding text
        ("450 4.1.1 mailbox unavailable, try later", "soft", "retry", "text-user-unknown"),
        ("450 mailbox unavailable", "soft", "retry", "text-user-unknown"),
        # basic reply codes only
        ("550 Rejected", "hard", "suppress", "smtp-550"),
        ("451 Local error", "soft", "retry", "smtp-451"),
        # nothing recognizable
        ("thanks for your message", "unknown", "investigate", "unmatched"),
    ],
)  # fmt: skip
def test_classification_rules(text, classification, action, rule):
    result = bc.classify(text)
    assert (result["classification"], result["action"], result["rule"]["id"]) == (
        classification,
        action,
        rule,
    ), result


def test_code_extraction_ignores_ip_addresses():
    assert bc.extract_codes("from 192.0.2.25 blocked") == (None, None)
    assert bc.extract_codes("550-5.7.1 nope") == ("5.7.1", "550")


def test_retry_schedule_only_for_retry():
    assert bc.classify("4.2.2")["retry_after_minutes"] == list(bc.RETRY_SCHEDULE_MINUTES)
    assert bc.classify("5.1.1")["retry_after_minutes"] == []


def test_provider_and_confidence():
    result = bc.classify("550 5.5.0 Requested action not taken: mailbox unavailable")
    assert result["provider"] == "Microsoft" and result["confidence"] == "high"
    assert bc.classify("550 Rejected")["confidence"] == "low"


def test_classify_one_envelope():
    result = bc.classify_one("550 5.1.1 user unknown")
    assert result["tool"] == "bounce-classify"
    assert result["target"] == "5.1.1"
    assert result["findings"][0]["status"] == "fail"


def test_cli_argument_json():
    result = runner.invoke(app, ["bounce-classify", "5.1.1", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["classification"] == "hard" and data["action"] == "suppress"


def test_cli_stdin_human():
    result = runner.invoke(app, ["bounce-classify"], input="452 4.2.2 Mailbox full\n")
    assert result.exit_code == 0, result.output
    text = unstyle(result.output)
    assert "SOFT" in text and "retry" in text and "4.2.2" in text


def test_cli_batch_json():
    lines = "550 5.1.1 user unknown\n\n452 4.2.2 mailbox full\n554 5.7.1 spam detected\n"
    result = runner.invoke(app, ["bounce-classify", "--batch", "--json"], input=lines)
    data = json.loads(result.output)
    assert data["counts"] == {"hard": 1, "soft": 1, "block": 1}
    assert data["actions"] == {"suppress": 1, "retry": 1, "investigate": 1}
    assert [r["classification"] for r in data["results"]] == ["hard", "soft", "block"]
    human = unstyle(runner.invoke(app, ["bounce-classify", "--batch"], input=lines).output)
    assert "1 block, 1 hard, 1 soft" in human


def test_cli_empty_input_errors():
    result = runner.invoke(app, ["bounce-classify"], input="   ")
    assert result.exit_code == 2
