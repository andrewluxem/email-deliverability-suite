"""DKIM checks: probe selectors for a published key and flag short RSA keys."""

import base64
import binascii
from collections.abc import Sequence
from typing import Any

from deliv.checks import RETRY_HINT
from deliv.lib.dns import DNSClient, DNSLookupError, parse_tag_list
from deliv.lib.scoring import Finding, Status

#: Selectors probed when the user does not name their own. Covers Google Workspace, Microsoft 365,
#: and the defaults of most ESPs and self-hosted setups.
DEFAULT_DKIM_SELECTORS: tuple[str, ...] = (
    "google",
    "selector1",
    "selector2",
    "default",
    "k1",
    "k2",
    "dkim",
)


def estimate_rsa_bits(public_key_b64: str) -> int | None:
    """Estimate the RSA modulus size from a DKIM ``p=`` value (None when it cannot be decoded)."""
    try:
        der = base64.b64decode(public_key_b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(der) < 64:
        return None
    # SubjectPublicKeyInfo overhead for RSA is roughly 38 bytes; round to the nearest 512 bits.
    bits = (len(der) - 38) * 8
    return max(512, round(bits / 512) * 512)


def check_dkim(client: DNSClient, domain: str, selectors: Sequence[str]) -> list[Finding]:
    """Probe DKIM selectors and report which ones publish a usable key."""
    category = "DKIM"
    found: dict[str, dict[str, Any]] = {}
    revoked: list[str] = []
    errors: list[str] = []
    for selector in selectors:
        name = f"{selector}._domainkey.{domain}"
        try:
            records = client.txt(name)
        except DNSLookupError as exc:
            errors.append(f"{selector} ({exc.reason})")
            continue
        for record in records:
            tags = parse_tag_list(record)
            if "p" not in tags or ("v" in tags and tags["v"].upper() != "DKIM1"):
                continue
            if not tags["p"]:
                revoked.append(selector)
                break
            key_type = tags.get("k", "rsa").lower()
            bits = estimate_rsa_bits(tags["p"]) if key_type == "rsa" else None
            found[selector] = {"key_type": key_type, "approx_bits": bits}
            break

    details = {
        "probed": list(selectors),
        "found": found,
        "revoked": revoked,
        "errors": errors,
    }
    if found:
        weak = [
            s for s, info in found.items() if info["approx_bits"] and info["approx_bits"] < 1024
        ]
        short = [s for s, info in found.items() if info["approx_bits"] == 1024]
        names = ", ".join(found)
        if weak:
            return [
                Finding(
                    "DKIM",
                    Status.FAIL,
                    f"DKIM key(s) under 1024 bits at selector(s): {', '.join(weak)}.",
                    "Rotate to a 2048-bit RSA key; many receivers ignore keys this short.",
                    category,
                    weight=3,
                    details=details,
                )
            ]
        if short:
            return [
                Finding(
                    "DKIM",
                    Status.WARN,
                    f"DKIM found at {names}, but {', '.join(short)} uses a 1024-bit key.",
                    "Rotate to a 2048-bit RSA key at your next key rotation.",
                    category,
                    weight=3,
                    details=details,
                )
            ]
        return [
            Finding(
                "DKIM",
                Status.PASS,
                f"DKIM key published at selector(s): {names}.",
                None,
                category,
                weight=3,
                details=details,
            )
        ]
    if errors and not revoked:
        return [
            Finding(
                "DKIM",
                Status.WARN,
                f"Could not check DKIM selectors: {', '.join(errors)}.",
                RETRY_HINT,
                category,
                weight=3,
                details=details,
            )
        ]
    if revoked:
        message = f"Only revoked (empty) DKIM keys found at: {', '.join(revoked)}."
    else:
        message = f"No DKIM key found at the {len(selectors)} common selectors probed."
    return [
        Finding(
            "DKIM",
            Status.WARN,
            message,
            "Find your ESP's selector in its DNS setup page and rerun with --selector <name>. If "
            "you have none, enable custom DKIM signing for this domain.",
            category,
            weight=3,
            details=details,
        )
    ]
