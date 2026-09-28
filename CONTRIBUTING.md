# Contributing

Thanks for helping make `deliv` better.

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
python -m pip install -e ".[dev]"
ruff check . && ruff format --check . && pytest
```

## Ground rules

- Tests never touch the network. `tests/conftest.py` blocks sockets for every test; mock DNS and
  HTTP at the boundary instead.
- Use fictional domains (`example.com`, `example.net`, `example.org`) and documentation IP ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) in code, tests, and docs.
- Keep the dependency footprint small: Typer and dnspython at runtime, pytest and ruff for development.
