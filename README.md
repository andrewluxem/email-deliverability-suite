# email-deliverability-suite

`deliv` is a command-line toolkit for email deliverability: DNS authentication audits, spam-risk
scoring, pre-send QA gates, header analysis, bounce classification, blocklist checks, warmup
planning, and shareable reports. Every command supports `--json`.

## Install (from source)

```bash
python -m pip install -e ".[dev]"
deliv --version
```

## Development

```bash
ruff check . && ruff format --check . && pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a check and [SECURITY.md](SECURITY.md) for
reporting vulnerabilities. Licensed under [MIT](LICENSE).
