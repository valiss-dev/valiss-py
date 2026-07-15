"""HTTP client transport for message tokens: mint a fresh proof of origin per
outgoing request and speak the sending side of chain negotiation.

``Transport`` is an httpx auth hook (requires the ``httpx`` extra).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta

from .. import creds, token
from ..errors import ValissError
from ..message import DEFAULT_MESSAGE_TTL, checksum, issue_message
from ._core import audience, minter


try:
    import httpx
except ImportError:  # httpx is an optional extra; Transport needs it.
    httpx = None  # type: ignore[assignment]


if httpx is not None:

    class Transport(httpx.Auth):
        """httpx auth hook that mints a fresh message token per request — a proof
        of origin bound to the destination (host + path) and the exact request
        body, carried in the ``valiss-message-token`` header with the provenance
        chain embedded. The receiver verifies it offline against the operator key.
        Attach to a webhook-emitting client as ``httpx.Client(auth=Transport(creds))``.

        Build it from bundle creds (account token + user token + seed). ``ttl``
        overrides the default message-token window. ``negotiate=True`` sends
        chainless tokens and retransmits once with the chain in detached headers
        when the receiver answers ``valiss-chain: required`` — against a receiver
        with a chain cache the steady state is the bare token per message.
        """

        # httpx buffers the request body before auth_flow, so the checksum can be
        # computed and the request replayed on the negotiation retransmit.
        requires_request_body = True

        def __init__(
            self,
            c: creds.Creds,
            *,
            ttl: timedelta | None = None,
            negotiate: bool = False,
            now: Callable[[], datetime] | None = None,
        ):
            self._user, self._epoch = minter(c)
            self._account_token = c.account_token
            self._user_token = c.user_token
            self._ttl = ttl if ttl is not None else DEFAULT_MESSAGE_TTL
            self._negotiate = negotiate
            self._now = now

        def auth_flow(self, request):
            body = request.content
            host = request.headers.get("host") or request.url.host
            chain = None if self._negotiate else (self._account_token, self._user_token)
            tok = issue_message(
                self._user,
                audience=audience(host, request.url.path),
                checksum=checksum(body),
                ttl=self._ttl,
                epoch=self._epoch,
                chain=chain,
                now=self._now() if self._now is not None else None,
            )
            request.headers[token.HEADER_MESSAGE_TOKEN] = tok
            response = yield request
            if not self._negotiate:
                return
            if (
                response.status_code == 401
                and response.headers.get(token.HEADER_CHAIN) == token.CHAIN_REQUIRED
            ):
                # The receiver does not know our chain: retransmit once with the
                # chain detached alongside the same still-valid token.
                request.headers[token.HEADER_CHAIN_ACCOUNT_TOKEN] = self._account_token
                request.headers[token.HEADER_CHAIN_USER_TOKEN] = self._user_token
                yield request

else:

    class Transport:  # type: ignore[no-redef]
        def __init__(self, *args: object, **kwargs: object):
            raise ValissError(
                "valiss: httpsig.Transport requires httpx; install the valiss[httpx] extra"
            )
