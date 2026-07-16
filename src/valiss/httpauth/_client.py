"""HTTP client credential attachment: ``credential_headers`` for any client,
``Auth`` as an httpx auth hook (requires the ``httpx`` extra), and
``RequestsAuth`` as a requests auth hook (requires the ``requests`` extra)."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import datetime

from .. import creds, token
from .._requests import host_path
from ..errors import ValissError
from .extension import request_context


def credential_headers(
    c: creds.Creds,
    method: str = "",
    host: str = "",
    path: str = "",
    *,
    nonce: str = "",
    now: Callable[[], datetime] | None = None,
) -> dict[str, str]:
    """Headers a client attaches to one request: the creds' tokens and, when
    the creds hold a seed, a fresh signature bound to the request's method,
    host, and path. Creds without a seed are bearer credentials: the server
    accepts them only when the effective token is a bearer user token.

    Pass ``nonce=token.new_nonce()`` when the server has a replay cache; the
    nonce is sent in its own header and folded into the signature. Signatures
    are single-use by freshness: build a new header set per request.
    """
    headers: dict[str, str] = {}
    if c.account_token:
        headers[token.HEADER_ACCOUNT_TOKEN] = c.account_token
    if c.user_token:
        headers[token.HEADER_USER_TOKEN] = c.user_token
    signer = c.signer()
    if signer is not None:
        if nonce:
            headers[token.HEADER_NONCE] = nonce
        timestamp, signature = token.sign_request(
            signer,
            request_context(method, host, path, nonce),
            now() if now is not None else None,
        )
        headers[token.HEADER_TIMESTAMP] = timestamp
        headers[token.HEADER_SIGNATURE] = signature
    return headers


try:
    import httpx
except ImportError:  # httpx is an optional extra; Auth needs it, the rest does not.
    httpx = None  # type: ignore[assignment]


if httpx is not None:

    class Auth(httpx.Auth):
        """httpx auth hook that attaches the creds' tokens and, when the creds
        hold a seed, a fresh per-request signature bound to the request's
        method, host, and path.

        Pass as ``httpx.Client(auth=Auth(creds_))``. ``nonce=True`` attaches a
        fresh per-request nonce (folded into the signature) so a server with a
        replay cache can suppress replays.
        """

        def __init__(
            self,
            c: creds.Creds,
            *,
            nonce: bool = False,
            now: Callable[[], datetime] | None = None,
        ):
            c.signer()  # fail fast on a malformed seed
            self._creds = c
            self._nonce = nonce
            self._now = now

        def auth_flow(self, request: httpx.Request) -> Iterator[httpx.Request]:
            request.headers.update(
                credential_headers(
                    self._creds,
                    request.method,
                    request.headers.get("host", request.url.host),
                    request.url.path,
                    nonce=token.new_nonce() if self._nonce else "",
                    now=self._now,
                )
            )
            yield request

else:

    class Auth:  # type: ignore[no-redef]
        def __init__(self, *args: object, **kwargs: object):
            raise ValissError(
                "valiss: httpauth.Auth requires httpx; install the valiss[httpx] extra"
            )


try:
    import requests
    import requests.auth
except ImportError:  # requests is an optional extra; RequestsAuth needs it, the rest does not.
    requests = None  # type: ignore[assignment]


if requests is not None:

    class RequestsAuth(requests.auth.AuthBase):
        """requests auth hook that attaches the creds' tokens and, when the
        creds hold a seed, a fresh per-request signature bound to the request's
        method, host, and path — the requests sibling of :class:`Auth`.

        Pass as ``requests.get(url, auth=RequestsAuth(creds_))`` or set it on a
        session. ``nonce=True`` attaches a fresh per-request nonce (folded into
        the signature) so a server with a replay cache can suppress replays.
        The signature binds the host the wire carries: an explicit Host header,
        or the URL's host with a non-default port kept.
        """

        def __init__(
            self,
            c: creds.Creds,
            *,
            nonce: bool = False,
            now: Callable[[], datetime] | None = None,
        ):
            c.signer()  # fail fast on a malformed seed
            self._creds = c
            self._nonce = nonce
            self._now = now

        def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
            host, path = host_path(request.url or "", request.headers.get("Host") or "")
            request.headers.update(
                credential_headers(
                    self._creds,
                    request.method or "",
                    host,
                    path,
                    nonce=token.new_nonce() if self._nonce else "",
                    now=self._now,
                )
            )
            return request

else:

    class RequestsAuth:  # type: ignore[no-redef]
        def __init__(self, *args: object, **kwargs: object):
            raise ValissError(
                "valiss: httpauth.RequestsAuth requires requests; "
                "install the valiss[requests] extra"
            )
