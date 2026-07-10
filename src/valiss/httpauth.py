"""HTTP client side of the valiss authentication scheme.

``credential_headers`` builds the per-request header set for any HTTP
client; ``Auth`` wraps it as an httpx auth hook. ``Ext`` is the HTTP
transport extension claim Go servers enforce; mint it into tokens with
``token.issue_user(..., extensions=[Ext(...)])``.

Requires the ``httpx`` extra only for the Auth class; everything else is
dependency-free.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from . import creds, token
from .errors import ValissError


@dataclass
class Ext:
    """HTTP transport extension claim: binds a token to specific hosts,
    methods, and paths.

    Enforcement on the Go server is fail-closed: every token in the chain
    must carry the extension (unless the middleware allows missing ones),
    and the zero-value extension grants nothing. A non-empty extension
    leaves its empty dimensions unconstrained, so ``Ext(paths=["/v1/*"])``
    permits any host and method under ``/v1/``; allow-all is the explicit
    ``Ext(paths=["*"])``.
    """

    # hosts allowed, matched exactly against the request Host.
    hosts: list[str] = field(default_factory=list)
    # methods allowed, matched exactly (upper-case, e.g. "GET").
    methods: list[str] = field(default_factory=list)
    # paths allowed; a trailing "*" is a prefix wildcard, so "/v1/*" covers
    # every path under /v1/.
    paths: list[str] = field(default_factory=list)

    def extension_name(self) -> str:
        return "http"

    def extension_payload(self) -> Mapping[str, Any]:
        payload: dict[str, Any] = {}
        if self.hosts:
            payload["hosts"] = self.hosts
        if self.methods:
            payload["methods"] = self.methods
        if self.paths:
            payload["paths"] = self.paths
        return payload


def credential_headers(
    c: creds.Creds, *, now: Callable[[], datetime] | None = None
) -> dict[str, str]:
    """Headers a client attaches to one request: the creds' tokens and,
    when the creds hold a seed, a fresh signature. Creds without a seed are
    bearer credentials: the server accepts them only when the effective
    token is a bearer user token.

    Signatures are single-use by freshness: build a new header set per
    request.
    """
    headers: dict[str, str] = {}
    if c.account_token:
        headers[token.HEADER_ACCOUNT_TOKEN] = c.account_token
    if c.user_token:
        headers[token.HEADER_USER_TOKEN] = c.user_token
    signer = c.signer()
    if signer is not None:
        timestamp, signature = token.sign_request(signer, now() if now is not None else None)
        headers[token.HEADER_TIMESTAMP] = timestamp
        headers[token.HEADER_SIGNATURE] = signature
    return headers


try:
    import httpx
except ImportError:  # httpx is an optional extra; Auth needs it, the rest does not.
    httpx = None  # type: ignore[assignment]


if httpx is not None:

    class Auth(httpx.Auth):
        """httpx auth hook that attaches the creds' tokens and, when the
        creds hold a seed, a fresh per-request signature.

        Pass as ``httpx.Client(auth=Auth(creds_))``.
        """

        def __init__(self, c: creds.Creds, *, now: Callable[[], datetime] | None = None):
            c.signer()  # fail fast on a malformed seed
            self._creds = c
            self._now = now

        def auth_flow(self, request: httpx.Request) -> Iterator[httpx.Request]:
            request.headers.update(credential_headers(self._creds, now=self._now))
            yield request

else:

    class Auth:  # type: ignore[no-redef]
        def __init__(self, *args: object, **kwargs: object):
            raise ValissError(
                "valiss: httpauth.Auth requires httpx; install the valiss[httpx] extra"
            )
