from types import SimpleNamespace
from unittest import mock

import dns.exception
import dns.resolver
import pytest

from deliv.lib.dns import (
    DNSClient,
    DNSLookupError,
    DNSTimeout,
    is_ip_address,
    make_dnspython_backend,
    normalize_domain,
    organizational_domain,
    parse_tag_list,
    reverse_ip,
)
from tests.fakes import FakeDNS


def test_client_returns_records_and_filters_prefix():
    fake = FakeDNS({("example.com", "TXT"): ["v=spf1 -all", "google-site-verification=abc"]})
    client = fake.client()
    assert client.txt("example.com.") == ["v=spf1 -all", "google-site-verification=abc"]
    assert client.txt_with_prefix("example.com", "V=SPF1") == ["v=spf1 -all"]
    assert client.txt("missing.example.com") == []


def test_client_parses_and_sorts_mx():
    fake = FakeDNS({("example.com", "MX"): ["20 mx2.example.com", "10 mx1.example.com", "bad"]})
    assert fake.client().mx("example.com") == [(10, "mx1.example.com"), (20, "mx2.example.com")]


def test_client_propagates_timeouts():
    fake = FakeDNS({("slow.example.com", "TXT"): "timeout"})
    with pytest.raises(DNSTimeout) as excinfo:
        fake.client(timeout=3).txt("slow.example.com")
    assert "3s" in str(excinfo.value)


def _txt_rdata(*chunks):
    return SimpleNamespace(strings=tuple(c.encode() for c in chunks))


def test_dnspython_backend_joins_txt_chunks():
    with mock.patch.object(dns.resolver.Resolver, "resolve") as resolve:
        resolve.return_value = [_txt_rdata("v=DKIM1; k=rsa; ", "p=ABC")]
        backend = make_dnspython_backend(["192.0.2.53"])
        assert backend("k1._domainkey.example.com", "TXT", 2) == ["v=DKIM1; k=rsa; p=ABC"]
        assert resolve.call_args.kwargs["lifetime"] == 2


def test_dnspython_backend_formats_mx():
    rdata = SimpleNamespace(preference=10, exchange="mx.example.net.")
    with mock.patch.object(dns.resolver.Resolver, "resolve", return_value=[rdata]):
        assert make_dnspython_backend(["192.0.2.53"])("example.com", "MX", 2) == [
            "10 mx.example.net"
        ]


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (dns.resolver.NXDOMAIN(), []),
        (dns.resolver.NoAnswer(), []),
    ],
)
def test_dnspython_backend_missing_records_are_empty(exc, expected):
    with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=exc):
        assert make_dnspython_backend(["192.0.2.53"])("example.com", "TXT", 2) == expected


def test_dnspython_backend_maps_errors():
    backend = make_dnspython_backend(["192.0.2.53"])
    with (
        mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.exception.Timeout()),
        pytest.raises(DNSTimeout),
    ):
        backend("example.com", "TXT", 2)
    with (
        mock.patch.object(
            dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NoNameservers()
        ),
        pytest.raises(DNSLookupError, match="SERVFAIL"),
    ):
        backend("example.com", "TXT", 2)


def test_default_client_builds_without_network():
    assert DNSClient(timeout=1, nameservers=["192.0.2.53"]).timeout == 1


@pytest.mark.parametrize(
    ("value", "expected"),
    [(" Example.COM. ", "example.com"), ("user@Mail.Example.net", "mail.example.net")],
)
def test_normalize_domain(value, expected):
    assert normalize_domain(value) == expected


@pytest.mark.parametrize(
    ("domain", "org"),
    [
        ("example.com", "example.com"),
        ("news.mail.example.com", "example.com"),
        ("shop.example.co.uk", "example.co.uk"),
        ("localhost", "localhost"),
    ],
)
def test_organizational_domain(domain, org):
    assert organizational_domain(domain) == org


def test_ip_helpers():
    assert is_ip_address("192.0.2.10")
    assert is_ip_address("2001:db8::1")
    assert not is_ip_address("example.com")
    assert reverse_ip("192.0.2.10") == "10.2.0.192"
    assert reverse_ip("2001:db8::1").startswith("1.0.0.0.")
    assert reverse_ip("2001:db8::1").endswith("8.b.d.0.1.0.0.2")


def test_parse_tag_list():
    tags = parse_tag_list("v=DMARC1; P=reject; rua=mailto:a@example.com ; p=none; junk")
    assert tags == {"v": "DMARC1", "p": "reject", "rua": "mailto:a@example.com"}
    assert parse_tag_list("v=DKIM1; p=MIGf MA0G")["p"] == "MIGfMA0G"
