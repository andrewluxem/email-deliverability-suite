"""Shared DNS query helpers with timeout handling.

All deliv tools resolve DNS through :class:`DNSClient`. The client wraps a *backend*: a callable
``backend(name, rdtype, timeout) -> list[str]`` that returns records as text. The default backend
uses dnspython. Tests swap in a fake backend so no test ever touches real DNS.

Semantics every tool can rely on:

* A name that does not exist, or has no records of the requested type, returns an empty list.
* A lookup that runs out of time raises :class:`DNSTimeout`.
* Any other resolver failure (SERVFAIL, refused, no reachable nameservers) raises
  :class:`DNSLookupError`.
"""

import ipaddress
from collections.abc import Callable, Sequence

import dns.exception
import dns.resolver

#: Default per-query timeout in seconds, shared by every command's ``--timeout`` option.
DEFAULT_TIMEOUT = 10.0

Backend = Callable[[str, str, float], list[str]]


class DNSLookupError(Exception):
    """A DNS query failed for a reason other than "no such record"."""

    def __init__(self, name: str, rdtype: str, reason: str) -> None:
        super().__init__(f"{rdtype} lookup for {name} failed: {reason}")
        self.name = name
        self.rdtype = rdtype
        self.reason = reason


class DNSTimeout(DNSLookupError):
    """A DNS query did not complete within its timeout."""

    def __init__(self, name: str, rdtype: str, timeout: float) -> None:
        super().__init__(name, rdtype, f"timed out after {timeout:g}s")
        self.timeout = timeout


def _rdata_to_text(rdata: object, rdtype: str) -> str:
    """Convert one dnspython rdata object to plain text.

    TXT records are split into 255-byte character strings on the wire; they are joined back
    together here so callers always see one string per record.
    """
    if rdtype == "TXT":
        strings = getattr(rdata, "strings", ())
        return b"".join(strings).decode("utf-8", errors="replace")
    if rdtype == "MX":
        exchange = str(getattr(rdata, "exchange", "")).rstrip(".")
        return f"{getattr(rdata, 'preference', 0)} {exchange}"
    return str(rdata).rstrip(".")


def make_dnspython_backend(nameservers: Sequence[str] | None = None) -> Backend:
    """Build the default backend on top of :mod:`dns.resolver`.

    Args:
        nameservers: Optional nameserver IPs to use instead of the system resolver configuration.
    """
    resolver = dns.resolver.Resolver(configure=not nameservers)
    if nameservers:
        resolver.nameservers = list(nameservers)

    def backend(name: str, rdtype: str, timeout: float) -> list[str]:
        try:
            answer = resolver.resolve(name, rdtype, lifetime=timeout, search=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.Timeout as exc:
            raise DNSTimeout(name, rdtype, timeout) from exc
        except dns.resolver.NoNameservers as exc:
            raise DNSLookupError(name, rdtype, "no nameserver answered (SERVFAIL/REFUSED)") from exc
        except dns.exception.DNSException as exc:
            raise DNSLookupError(name, rdtype, str(exc) or type(exc).__name__) from exc
        return [_rdata_to_text(rdata, rdtype) for rdata in answer]

    return backend


class DNSClient:
    """Small DNS facade used by every tool.

    Args:
        timeout: Per-query timeout in seconds.
        backend: Optional replacement backend (tests pass a fake here).
        nameservers: Optional nameserver IPs for the default dnspython backend.
    """

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        backend: Backend | None = None,
        nameservers: Sequence[str] | None = None,
    ) -> None:
        self.timeout = timeout
        self._backend = backend or make_dnspython_backend(nameservers)

    def query(self, name: str, rdtype: str) -> list[str]:
        """Run one query and return the records as text (empty when none exist)."""
        return self._backend(name.rstrip("."), rdtype.upper(), self.timeout)

    def txt(self, name: str) -> list[str]:
        """Return every TXT record at ``name``."""
        return self.query(name, "TXT")

    def a(self, name: str) -> list[str]:
        """Return every A record at ``name``."""
        return self.query(name, "A")

    def aaaa(self, name: str) -> list[str]:
        """Return every AAAA record at ``name``."""
        return self.query(name, "AAAA")

    def mx(self, name: str) -> list[tuple[int, str]]:
        """Return ``(preference, exchange)`` pairs at ``name``, sorted by preference."""
        pairs: list[tuple[int, str]] = []
        for record in self.query(name, "MX"):
            preference, _, exchange = record.partition(" ")
            try:
                pairs.append((int(preference), exchange.rstrip(".")))
            except ValueError:
                continue
        return sorted(pairs)

    def txt_with_prefix(self, name: str, prefix: str) -> list[str]:
        """Return TXT records at ``name`` that start with ``prefix`` (case-insensitive)."""
        wanted = prefix.lower()
        return [r for r in self.txt(name) if r.strip().lower().startswith(wanted)]


def normalize_domain(value: str) -> str:
    """Lower-case a domain and strip whitespace, a trailing dot, and any ``user@`` prefix."""
    value = value.strip().lower()
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    return value.rstrip(".")


def is_ip_address(value: str) -> bool:
    """Return True when ``value`` is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


def reverse_ip(value: str) -> str:
    """Return the DNSBL-style reversed form of an IP address.

    IPv4 ``192.0.2.10`` becomes ``10.2.0.192``; IPv6 addresses are expanded to reversed nibbles.
    """
    ip = ipaddress.ip_address(value.strip())
    if ip.version == 4:
        return ".".join(reversed(str(ip).split(".")))
    return ".".join(reversed(ip.exploded.replace(":", "")))


#: Two-label public suffixes common enough to matter for organizational-domain alignment.
#: This is a deliberately small built-in list (no Public Suffix List dependency); it covers the
#: country-code second-level domains most senders use.
MULTI_LABEL_SUFFIXES = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "org.nz", "net.nz",
        "co.jp", "ne.jp", "or.jp", "ac.jp",
        "com.br", "net.br", "org.br",
        "com.mx", "org.mx",
        "co.in", "net.in", "org.in", "firm.in",
        "co.za", "org.za",
        "com.sg", "com.hk", "com.tw", "com.cn", "net.cn", "org.cn",
        "co.kr", "or.kr",
        "com.tr", "com.ar", "com.co", "com.pe", "com.ph", "com.my",
        "co.il", "co.id", "co.th",
    }
)  # fmt: skip


def organizational_domain(domain: str) -> str:
    """Approximate the DMARC organizational domain (registrable domain) of ``domain``.

    ``news.mail.example.com`` becomes ``example.com`` and ``shop.example.co.uk`` becomes
    ``example.co.uk``. Uses :data:`MULTI_LABEL_SUFFIXES` rather than the full Public Suffix List.
    """
    labels = normalize_domain(domain).split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def parse_tag_list(record: str) -> dict[str, str]:
    """Parse a ``tag=value; tag=value`` record (DMARC, DKIM, BIMI, MTA-STS, TLS-RPT).

    Tag names are lower-cased; values keep their case with surrounding whitespace removed. When a
    tag repeats, the first occurrence wins.
    """
    tags: dict[str, str] = {}
    for part in record.split(";"):
        name, sep, value = part.partition("=")
        if not sep:
            continue
        name = name.strip().lower()
        if name and name not in tags:
            tags[name] = "".join(value.split()) if name in {"p", "b", "bh"} else value.strip()
    return tags
