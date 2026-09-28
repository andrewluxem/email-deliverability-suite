import socket

import pytest
from typer.testing import CliRunner

from deliv import __version__
from deliv.cli import app

runner = CliRunner()


def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_no_args_shows_help():
    result = runner.invoke(app, [])
    assert "deliverability" in result.output.lower()


def test_network_is_blocked_in_tests():
    with pytest.raises(RuntimeError):
        socket.socket()
