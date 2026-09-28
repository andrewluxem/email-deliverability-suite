"""Test doubles for the network boundary: a fake DNS backend and a fake HTTPS fetcher."""

from deliv.lib.dns import DNSClient, DNSLookupError, DNSTimeout
from deliv.lib.http import FetchError


class FakeDNS:
    """In-memory DNS backend keyed by (name, rdtype).

    Values may be a list of record strings, or an exception instance to raise
    ("timeout" and "servfail" are accepted as shorthands).
    """

    def __init__(self, records=None):
        self.records = {}
        self.queries = []
        for (name, rdtype), value in (records or {}).items():
            self.add(name, rdtype, value)

    def add(self, name, rdtype, value):
        self.records[(name.lower().rstrip("."), rdtype.upper())] = value
        return self

    def __call__(self, name, rdtype, timeout):
        self.queries.append((name, rdtype))
        value = self.records.get((name.lower(), rdtype), [])
        if value == "timeout":
            raise DNSTimeout(name, rdtype, timeout)
        if value == "servfail":
            raise DNSLookupError(name, rdtype, "SERVFAIL")
        if isinstance(value, Exception):
            raise value
        return list(value)

    def client(self, timeout=2.0):
        return DNSClient(timeout=timeout, backend=self)


class FakeFetcher:
    """Fake HTTPS fetcher: maps URL to body text, or to an exception."""

    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []

    def __call__(self, url, timeout):
        self.calls.append(url)
        value = self.responses.get(url)
        if value is None:
            raise FetchError(f"could not fetch {url}: connection refused")
        if isinstance(value, Exception):
            raise value
        return value
