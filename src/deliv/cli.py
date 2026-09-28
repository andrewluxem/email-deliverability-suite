"""Typer application that wires every deliv subcommand together."""

import typer

from deliv import (
    __version__,
    blacklist,
    bounce_classify,
    copy_check,
    dns_audit,
    header_analyze,
    report,
    spam_scan,
    warmup_plan,
)

app = typer.Typer(
    name="deliv",
    help=(
        "Email deliverability toolkit. Audit DNS authentication, score copy for spam risk, "
        "gate sends before they go out, read message headers, classify bounces, check "
        "blocklists, plan IP/domain warmup, and roll it all into one shareable report.\n\n"
        "Every command accepts --json for machine-readable output."
    ),
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"deliv {__version__}")
        raise typer.Exit()


@app.callback()
def root(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the deliv version and exit.",
    ),
) -> None:
    """Email deliverability toolkit: graded, scriptable checks for marketers and developers."""


app.command("dns-audit")(dns_audit.command)
app.command("spam-scan")(spam_scan.command)
app.command("copy-check")(copy_check.command)
app.command("header-analyze")(header_analyze.command)
app.command("bounce-classify")(bounce_classify.command)
app.command("blacklist")(blacklist.command)
app.command("warmup-plan")(warmup_plan.command)
app.command("report")(report.command)


def main() -> None:
    """Console-script entry point for the ``deliv`` command."""
    app()


if __name__ == "__main__":
    main()
