"""Minimal HTTPS fetch helper (standard library only) with timeouts and no redirects."""

import urllib.error
import urllib.request
from collections.abc import Callable

from deliv import __version__

#: Callable signature tools accept so tests can inject a fake fetcher.
Fetcher = Callable[[str, float], str]


class FetchError(Exception):
    """An HTTP fetch failed (network error, timeout, redirect, bad status, or oversized body)."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        raise FetchError(f"server redirected to {newurl} (redirects are not allowed here)")


def fetch_text(url: str, timeout: float, max_bytes: int = 64 * 1024) -> str:
    """Fetch ``url`` over HTTPS and return the body as text.

    Redirects are refused (RFC 8461 forbids them for MTA-STS policies) and bodies larger than
    ``max_bytes`` raise :class:`FetchError`.
    """
    if not url.lower().startswith("https://"):
        raise FetchError("only https:// URLs are fetched")
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, headers={"User-Agent": f"deliv/{__version__}"})
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(max_bytes + 1)
    except FetchError:
        raise
    except urllib.error.HTTPError as exc:
        raise FetchError(f"HTTP {exc.code} from {url}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise FetchError(f"could not fetch {url}: {reason}") from exc
    if len(body) > max_bytes:
        raise FetchError(f"response from {url} is larger than {max_bytes} bytes")
    return body.decode("utf-8", errors="replace")
