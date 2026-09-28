"""Reusable fake-DNS zones for dns-audit tests. Fictional domains only."""

import base64

from tests.fakes import FakeDNS, FakeFetcher

KEY_2048 = base64.b64encode(bytes(294)).decode()
KEY_1024 = base64.b64encode(bytes(162)).decode()
KEY_512 = base64.b64encode(bytes(94)).decode()

POLICY_URL = "https://mta-sts.example.com/.well-known/mta-sts.txt"
ENFORCE_POLICY = "version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 604800\n"


def healthy_zone():
    """A domain that passes every check."""
    return FakeDNS(
        {
            ("example.com", "TXT"): [
                "v=spf1 include:_spf.esp.example.net ip4:192.0.2.0/24 -all",
                "site-verification=abc123",
            ],
            ("_spf.esp.example.net", "TXT"): ["v=spf1 ip4:198.51.100.0/24 ~all"],
            ("k1._domainkey.example.com", "TXT"): [f"v=DKIM1; k=rsa; p={KEY_2048}"],
            ("_dmarc.example.com", "TXT"): [
                "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:ruf@example.com"
            ],
            ("default._bimi.example.com", "TXT"): [
                "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"
            ],
            ("_mta-sts.example.com", "TXT"): ["v=STSv1; id=20260101T000000"],
            ("example.com", "MX"): ["10 mx1.example.com", "20 mx2.example.com"],
            ("_smtp._tls.example.com", "TXT"): ["v=TLSRPTv1; rua=mailto:tls@example.com"],
        }
    )


def healthy_fetcher():
    return FakeFetcher({POLICY_URL: ENFORCE_POLICY})
