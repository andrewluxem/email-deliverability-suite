# Contributing

Thanks for helping make `deliv` better. Deliverability knowledge goes stale quickly. Mailbox providers change their
rules, blocklists shut down, and ESPs rename things, so the most useful contributions are usually a new check, a
new bounce pattern, or a correction to an existing one.

## Development setup

```bash
git clone https://github.com/andrewluxem/email-deliverability-suite
cd email-deliverability-suite
python -m venv .venv && source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Run the same checks CI runs before you open a pull request:

```bash
ruff check .
ruff format --check .
pytest
```

CI runs these on Python 3.10, 3.11, and 3.12.

## Ground rules

- **No network in tests, ever.** `tests/conftest.py` replaces `socket.socket` for every test, so a test that tries
  to reach the network fails loudly. Mock at the boundary instead: `tests/fakes.py` provides `FakeDNS` (pass it to
  code as `FakeDNS(...).client()`) and `FakeFetcher` (for HTTPS).
- **Fictional data only.** Use `example.com`, `example.net`, and `example.org` for domains, and the documentation
  ranges `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24` for IPs. Never commit real customer mail, real
  headers, or real addresses. If you are reporting a bug found on real mail, redact it to these values first.
- **Small dependency footprint.** Typer and dnspython at runtime, and pytest and ruff for development. Open an issue
  before proposing anything else.
- **Every public function has type hints and a docstring**, and every command's `--help` should make sense to a
  marketer, not just an engineer.
- **Every non-pass finding carries a remediation.** A WARN or FAIL without a fix tells the user nothing they can
  act on.

## Adding a new check

Most checks are a function that returns one or more `Finding` objects (`deliv.lib.scoring`).

1. **Pick the home.** DNS authentication checks go in `src/deliv/checks/`, one module per protocol. Content checks
   go in `copy_check.py`. Header checks go in `header_analyze.py`.
2. **Write the check.** Return `Finding(check, status, message, remediation, category, weight=...)`.
   - `message` is one plain-English sentence that says what was found.
   - `remediation` says what to do. It is required for WARN and FAIL.
   - `weight` sets how much the check moves the score (DNS core checks use 3, minor ones 0.5-1). Use `weight=0`
     or `Status.INFO` for anything that should be reported but not graded.
   - Set `critical=True` only when a failure should cap the whole grade at F on its own.
   - Network lookups go through the `DNSClient` you are given. Catch `DNSLookupError` (which includes
     `DNSTimeout`) and turn it into a WARN that suggests `--timeout` or `--nameserver`. Never let it crash the
     command.
3. **Wire it in.** Call it from the tool's orchestrating function (`audit_domain`, `check_content`, and so on).
4. **Test it.** Add tests under `tests/`, mirroring the source path (for example
   `src/deliv/checks/spf.py` is tested in `tests/checks/test_spf.py`). A pull request needs at least:
   - one test where the check passes,
   - one test for each WARN and FAIL branch,
   - for any network check, one test where the lookup times out or errors.
5. **Document it** in the tool's section of `README.md`, and in `skills/deliverability/SKILL.md` if it changes how
   results should be read.

## Adding a spam-trigger phrase or category

Triggers live in `data/spam_triggers.json`:

```json
{
  "categories": {
    "urgency": {
      "description": "Pressure language that manufactures a deadline.",
      "phrases": [
        {"phrase": "act now", "weight": 6, "rewrite": "Say what happens and when: 'The sale ends Friday at midnight.'"}
      ]
    }
  }
}
```

- `weight` runs from 1 (mild) to 10 (near-certain filter hit). Compare your phrase with its neighbors in the same
  category before you pick a number.
- `rewrite` is required. It is what users see in the "suggested rewrites" list, so make it an actual alternative,
  not "avoid this".
- Phrases are matched case-insensitively on word boundaries. Whitespace inside a phrase matches any run of spaces
  or line breaks. Do not add a phrase that is already covered by an existing one.
- **A new category** needs a `description` and at least five phrases. Add it to the category list in
  `test_dataset_is_curated_and_large_enough` in `tests/test_spam_scan.py`, and add a test that shows at least one
  of its phrases matching realistic copy.
- **A new formatting pattern** is code, not a phrase. Add the regex to `_PATTERNS` in `src/deliv/spam_scan.py`
  and its weight to the `formatting.patterns` object in the JSON, and add a case to `test_formatting_patterns`.

`test_dataset_is_curated_and_large_enough` enforces unique phrases, valid weights, and non-empty rewrites.

## Adding a bounce rule or blocklist

- **Bounce rules** are in `src/deliv/bounce_classify.py`. Provider-specific wording goes in `PROVIDER_RULES`,
  and exact enhanced codes go in `SPECIFIC_CODES`. Add the real (redacted) bounce text as a case in
  `test_classification_rules`.
- **Blocklists** are in `BLOCKLISTS` in `src/deliv/blacklist.py`. Before you add one, confirm it still answers
  its published test entry (usually `127.0.0.2`), and record its access terms and delisting URL. The README table
  documents registration requirements and query limits, so update it too.

## Recording a demo

A short terminal recording makes a pull request (or the README) much easier to review.

**asciinema** (recommended, since the result is text and stays small):

```bash
pipx install asciinema
asciinema rec demo.cast --idle-time-limit 2 --title "deliv demo"
# in the recording:
deliv dns-audit example.com
deliv copy-check tests/fixtures/promo_spammy.html
deliv header-analyze tests/fixtures/esp_misaligned.eml
exit
asciinema upload demo.cast   # or attach demo.cast to the PR
```

**GIF** for the README: convert the cast with [agg](https://github.com/asciinema/agg):

```bash
agg --cols 110 --rows 32 --font-size 16 demo.cast docs/demo.gif
```

Keep recordings under 30 seconds, and use only the fixtures in `tests/fixtures/` or fictional domains. `*.cast`
files are gitignored, so commit only the rendered GIF, and only when it replaces an older one.

## Pull requests

- Use conventional commit messages: `feat:`, `fix:`, `test:`, `docs:`, `chore:`.
- Keep each pull request to one change. A new check and an unrelated refactor belong in separate pull requests.
- Explain the real-world failure the change catches, and link a source (an RFC, mailbox-provider documentation, or
  a blocklist policy page) where you can.
