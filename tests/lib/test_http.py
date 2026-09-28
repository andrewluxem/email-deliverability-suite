import io
import urllib.error
from unittest import mock

import pytest

from deliv.lib import http
from deliv.lib.http import FetchError, fetch_text


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _opener_returning(value=None, error=None):
    opener = mock.Mock()
    if error:
        opener.open.side_effect = error
    else:
        opener.open.return_value = _Response(value)
    return opener


def test_only_https_is_allowed():
    with pytest.raises(FetchError, match="https"):
        fetch_text("http://mta-sts.example.com/", 1)


def test_fetch_returns_text():
    with mock.patch.object(
        http.urllib.request, "build_opener", return_value=_opener_returning(b"ok")
    ):
        assert fetch_text("https://mta-sts.example.com/x", 1) == "ok"


def test_fetch_rejects_oversized_body():
    opener = _opener_returning(b"x" * 20)
    with (
        mock.patch.object(http.urllib.request, "build_opener", return_value=opener),
        pytest.raises(FetchError, match="larger"),
    ):
        fetch_text("https://mta-sts.example.com/x", 1, max_bytes=10)


@pytest.mark.parametrize(
    "error",
    [
        urllib.error.URLError("timed out"),
        urllib.error.HTTPError("https://x", 404, "nf", {}, None),
        TimeoutError(),
        FetchError("server redirected"),
    ],
)
def test_fetch_errors_become_fetch_error(error):
    with (
        mock.patch.object(
            http.urllib.request, "build_opener", return_value=_opener_returning(error=error)
        ),
        pytest.raises(FetchError),
    ):
        fetch_text("https://mta-sts.example.com/x", 1)


def test_redirects_are_refused():
    handler = http._NoRedirect()
    with pytest.raises(FetchError, match="redirect"):
        handler.redirect_request(None, None, 301, "moved", {}, "https://elsewhere.example.net/")
