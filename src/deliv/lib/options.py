"""Reusable Typer option types so every command spells shared flags the same way."""

from typing import Annotated

import typer

from deliv.lib.dns import DEFAULT_TIMEOUT

JsonFlag = Annotated[
    bool,
    typer.Option(
        "--json",
        help="Print machine-readable JSON instead of the human report. Feed it to `deliv report`.",
    ),
]

TimeoutOption = Annotated[
    float,
    typer.Option(
        "--timeout",
        min=0.5,
        help=(
            "Seconds to wait for each network lookup. Slow or unreachable lookups become "
            "warnings, never crashes."
        ),
    ),
]

NameserverOption = Annotated[
    list[str] | None,
    typer.Option(
        "--nameserver",
        help="Use this DNS server IP instead of the system resolver. Repeat for several.",
    ),
]

__all__ = ["DEFAULT_TIMEOUT", "JsonFlag", "NameserverOption", "TimeoutOption"]
