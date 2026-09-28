"""Shared fixtures. Network access is blocked for every test, always."""

import socket

import pytest


class _NoNetworkSocket(socket.socket):
    def __init__(self, *args, **kwargs):
        raise RuntimeError("Network access is disabled in tests. Mock DNS/HTTP at the boundary.")


@pytest.fixture(autouse=True)
def _block_network(monkeypatch):
    monkeypatch.setattr(socket, "socket", _NoNetworkSocket)
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("Network access is disabled in tests.")),
    )
