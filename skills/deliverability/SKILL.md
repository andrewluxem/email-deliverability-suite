---
name: deliverability
description: Use when auditing email deliverability, checking SPF, DKIM, DMARC, BIMI, MTA-STS or TLS-RPT records, running a pre-send QA gate on an email before it ships, scoring email copy for spam-filter risk, diagnosing why mail lands in spam from message headers, classifying bounces for suppression, checking an IP or domain against DNS blocklists (Spamhaus, Barracuda, SpamCop), planning IP or domain warmup, or producing a deliverability report. Wraps the `deliv` CLI from email-deliverability-suite.
---

# Email deliverability with `deliv`

`deliv` is a tested CLI with eight subcommands. Each one prints a readable report, and with `--json` it returns
machine-readable output you can parse. Run the commands. Do not recreate their logic by hand.

## Setup

```bash
deliv --version || pipx install git+https://github.com/andrewluxem/email-deliverability-suite
```

## Pick the command

| The user wants to... | Run |
| --- | --- |
| Check a domain's email authentication DNS | `deliv dns-audit <domain> --json` |
| Know if copy will trip spam filters | `deliv spam-scan <file> --json` |
| Gate an email before sending (go / no-go) | `deliv copy-check <file> --json` |
| Know why a delivered message failed auth or landed in spam | `deliv header-analyze <file.eml> --json` |
| Decide whether to suppress a bounced address | `deliv bounce-classify "<bounce text>" --json` |
| Check whether an IP or domain is blocklisted | `deliv blacklist <ip-or-domain> --json` |
| Ramp volume on a new IP or domain | `deliv warmup-plan --esp gmail --start-volume 50 --target-volume 50000 --days 30 --json` |
| Hand someone a single shareable report | `deliv report --input results.json --format html --output report.html` |

Useful flags:

- `dns-audit --selector <name>` probes the ESP's DKIM selector as well as the common defaults. If DKIM comes back
  WARN with "no key found", ask the user for their selector (their ESP's DNS setup page lists it) and rerun.
- `dns-audit` and `blacklist` accept `--timeout <seconds>` (default 10) and `--nameserver <ip>`.
- `blacklist --no-verify` skips the test-entry check. Keep it on unless you are rate-limited.
- `copy-check` and `spam-scan` read `.html`, `.txt`, or `.eml`, or `-` for stdin. Prefer an `.eml` test send when
  one is available, because only `.eml` input lets copy-check verify the List-Unsubscribe headers.
- `bounce-classify --batch` reads one bounce per line from stdin.

## Interpret the results

**Grades** (dns-audit, spam-scan, header-analyze, blacklist): A 90+, B 80-89, C 70-79, D 60-69, F under 60. A failed
*critical* check always caps the grade at F: a missing SPF or DMARC record, SPF `+all`, or a broken SPF record.
Each finding is `pass`, `warn`, `fail`, or `info`. `info` is never scored. Every `warn` and `fail` carries a
`remediation` string. Quote it rather than paraphrasing it.

**copy-check verdicts** and exit codes:

- `PASS` (0): safe to send.
- `REVIEW` (1): a human should look at the listed reasons first (e.g. no physical address detected).
- `FAIL` (2): block the send. Fix every reason listed before retrying.
- Exit code 3 means the input file could not be read. It is not a verdict.

**blacklist statuses**: `listed` (fail, with a delisting URL), `clean`, `error` (timeout, rate limit, or refused
resolver), `unverified` (the list did not confirm its own test entry, so its "clean" cannot be trusted), and
`skipped` (a retired list). Never tell the user an IP is clean on Spamhaus when the status is `unverified`.
Tell them to rerun with `--nameserver` pointed at their own resolver.

**bounce-classify**: `classification` is `hard`, `soft`, `block`, or `unknown`, and `action` is `suppress`, `retry`,
or `investigate`. `block` means the problem is on the sending side (reputation, authentication, content), so never
suppress the recipient for a block. Check `confidence`: `low` means only a bare SMTP code matched.

**warmup-plan** output is planning guidance, not a guarantee of inbox placement. Say so when you present it.

## Report back

1. Lead with the grade or verdict and the one-line `summary`.
2. List every `fail`, then every `warn`, each with its `remediation`.
3. For several checks, save each `--json` output and build one report:

```bash
deliv dns-audit example.com --json > dns.json
deliv copy-check campaign.html --json > qa.json
deliv report -i dns.json -i qa.json --format html -o deliverability-report.html
```

## Worked example 1: DNS audit

User: "Why is example.com mail going to spam? Check our DNS."

```bash
deliv dns-audit example.com --json
```

The (abridged) result:

```json
{"tool": "dns-audit", "target": "example.com", "score": 76, "grade": "C",
 "findings": [
  {"check": "SPF lookups", "status": "warn", "message": "SPF uses 9 of 10 DNS lookups. One more sender breaks it.",
   "remediation": "Flatten or remove includes before adding another sending service."},
  {"check": "DKIM", "status": "warn", "message": "No DKIM key found at the 7 common selectors probed.",
   "remediation": "Find your ESP's selector in its DNS setup page and rerun with --selector <name>. ..."},
  {"check": "DMARC policy", "status": "warn", "message": "Policy is p=none: you get reports, but spoofed mail is still delivered.",
   "remediation": "Review rua reports, fix any legitimate senders that fail, then move to p=quarantine and later p=reject."}]}
```

Before answering, ask for the ESP's DKIM selector and rerun with `--selector`. If DKIM is actually missing, that is
the most likely cause of the spam placement. Then answer: "Grade C. Three fixes, in order: publish DKIM for
example.com, trim SPF includes (9 of 10 lookups used), and move DMARC from p=none to p=quarantine once reports are
clean."

## Worked example 2: pre-send gate

User: "Can we send spring-sale.html tomorrow?"

```bash
deliv copy-check spring-sale.html --json; echo "exit=$?"
```

The result is `"verdict": "FAIL"` with `exit=2`, and these `reasons`:

```text
Spam score: Spam-risk grade F (48/100): copy is likely to be filtered.
Link shorteners: 1 shortened link(s) hide their destination: https://bit.ly/3xYz.
Unsubscribe link: No visible unsubscribe link in the body.
```

Answer: "Not yet. The gate fails on three blockers: replace the bit.ly link with a direct link to your domain, add an
unsubscribe link to the footer, and rewrite the top spam phrases." Then list the `rewrites` array, e.g. "Make money
fast" (line 5): remove it and describe the real offer. After the user edits the file, rerun `copy-check` and confirm
it returns exit 0 (PASS) or 1 (REVIEW, with the reasons explained) before calling it ready.

## In CI

```yaml
- run: pipx install git+https://github.com/andrewluxem/email-deliverability-suite
- run: deliv copy-check emails/campaign.html   # fails the job on FAIL (exit 2)
```

Treat exit code 1 (REVIEW) as a failure, or allow it, according to the team's policy.
