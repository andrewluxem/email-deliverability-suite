"""BIMI check: record presence, DMARC enforcement prerequisite, logo URL, and VMC."""

from deliv.checks import RETRY_HINT
from deliv.lib.dns import DNSClient, DNSLookupError, parse_tag_list
from deliv.lib.scoring import Finding, Status


def check_bimi(client: DNSClient, domain: str, dmarc_policy: str | None) -> list[Finding]:
    """Check the default BIMI record and whether it can actually display a logo."""
    category = "BIMI"
    name = f"default._bimi.{domain}"
    try:
        records = client.txt_with_prefix(name, "v=BIMI1")
    except DNSLookupError as exc:
        return [
            Finding(
                "BIMI",
                Status.INFO,
                f"Could not look up BIMI: {exc.reason}.",
                RETRY_HINT,
                category,
                weight=0,
            )
        ]
    if not records:
        return [
            Finding(
                "BIMI",
                Status.INFO,
                "No BIMI record (optional: shows your logo beside messages in supporting inboxes).",
                "BIMI needs DMARC at quarantine or reject, an SVG Tiny PS logo, and for Gmail and "
                "Apple Mail a Verified Mark Certificate (VMC) or Common Mark Certificate.",
                category,
                weight=0,
            )
        ]
    tags = parse_tag_list(records[0])
    details = {"record": records[0], "logo": tags.get("l"), "authority": tags.get("a")}
    if dmarc_policy not in {"quarantine", "reject"}:
        return [
            Finding(
                "BIMI",
                Status.WARN,
                "BIMI record exists, but DMARC is not at enforcement, so no logo will show.",
                "Move DMARC to p=quarantine or p=reject (pct=100).",
                category,
                weight=0.5,
                details=details,
            )
        ]
    if not tags.get("l", "").lower().startswith("https://"):
        return [
            Finding(
                "BIMI",
                Status.WARN,
                "BIMI l= must be an https:// URL to an SVG logo.",
                "Host the SVG Tiny PS logo over HTTPS and reference it in l=.",
                category,
                weight=0.5,
                details=details,
            )
        ]
    if not tags.get("a"):
        return [
            Finding(
                "BIMI",
                Status.WARN,
                "BIMI has no a= certificate, so Gmail and Apple Mail will not show the logo.",
                "Get a Verified Mark Certificate (VMC) or Common Mark Certificate and add its "
                "URL as a=.",
                category,
                weight=0.5,
                details=details,
            )
        ]
    return [
        Finding(
            "BIMI",
            Status.PASS,
            "BIMI record with logo and VMC certificate found.",
            None,
            category,
            weight=0.5,
            details=details,
        )
    ]
