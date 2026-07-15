"""Pure-ASGI server middleware for message tokens (proofs of origin) — works
with any ASGI app (Starlette, FastAPI, Quart, …).

:class:`Middleware` requires every request to carry a ``valiss-message-token``
proving the origin of its exact body at this destination, verified offline
against the operator key. The verified claims are stored on the request state
(``request.state.valiss_message``); read them with :func:`message_claims`, or in
FastAPI inject them with ``Depends(valiss_message)``. A missing or invalid token
gets 401; a chainless token whose chain is unknown gets the
``valiss-chain: required`` negotiation signal.

A message token proves origin only — it authenticates the message, not a caller.
Pair with ``valiss.httpauth`` when the caller must also authenticate.

Requires the ``fastapi`` extra (Starlette; FastAPI only for the ``Depends``
accessor).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ..chain import ChainCache
from ..keyring import Keyring
from ..message import MessageClaims
from .. import token as token_mod
from ._core import Reject, audience, authenticate_message, build_verifier

_STATE_KEY = "valiss_message"


class Middleware:
    """ASGI middleware verifying a message token on every HTTP request. Give
    exactly one trust anchor: ``operator_pub_key`` (single operator) or
    ``keyring`` (several). ``chain_cache`` remembers negotiated chains so an
    emitter pays the chain retransmit once, not per message; ``verify_options``
    passes extra keyword bindings to every ``verify_message`` call. Add it with
    ``app.add_middleware(Middleware, operator_pub_key=…)`` or wrap any ASGI app
    directly."""

    def __init__(
        self,
        app: ASGIApp,
        operator_pub_key: str | None = None,
        *,
        keyring: Keyring | None = None,
        chain_cache: ChainCache | None = None,
        verify_options: Mapping[str, Any] | None = None,
    ) -> None:
        self.app = app
        self._verify, self._verify_opts = build_verifier(operator_pub_key, keyring, verify_options)
        self._cache = chain_cache

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in scope["headers"]}
        tok = headers.get("valiss-message-token", "")
        if not tok:
            await _reject(send, "valiss: missing message token")
            return

        body, replay = await _buffer_body(receive)
        result = authenticate_message(
            self._verify,
            self._verify_opts,
            self._cache,
            token_str=tok,
            body=body,
            audience_str=audience(headers.get("host", ""), scope["path"]),
            chain_account=headers.get("valiss-chain-account-token", ""),
            chain_user=headers.get("valiss-chain-user-token", ""),
        )
        if isinstance(result, Reject):
            extra = (
                [(token_mod.HEADER_CHAIN.encode(), token_mod.CHAIN_REQUIRED.encode())]
                if result.chain_required
                else []
            )
            await _reject(send, result.message, extra_headers=extra)
            return

        scope.setdefault("state", {})[_STATE_KEY] = result
        await self.app(scope, replay, send)


async def _buffer_body(receive: Receive):
    """Drain the request body into bytes and return it with a replacement
    ``receive`` that replays it, so the downstream app can still read the body."""
    chunks: list[bytes] = []
    more = True
    while more:
        event = await receive()
        if event["type"] == "http.request":
            chunks.append(event.get("body", b""))
            more = event.get("more_body", False)
        elif event["type"] == "http.disconnect":
            break
    body = b"".join(chunks)

    replayed = False

    async def replay() -> Message:
        nonlocal replayed
        if not replayed:
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return body, replay


async def _reject(send: Send, message: str, *, extra_headers: list[tuple[bytes, bytes]] = []) -> None:
    payload = message.encode("utf-8")
    headers = [
        (b"content-type", b"text/plain; charset=utf-8"),
        (b"content-length", str(len(payload)).encode("ascii")),
        *extra_headers,
    ]
    await send({"type": "http.response.start", "status": 401, "headers": headers})
    await send({"type": "http.response.body", "body": payload})


def message_claims(request: Request) -> MessageClaims | None:
    """The verified message claims the middleware stored on the request state, or
    ``None`` when it did not run for this request."""
    return getattr(request.state, _STATE_KEY, None)


def valiss_message(request: Request) -> MessageClaims:
    """FastAPI dependency yielding the verified message claims: use as
    ``claims: MessageClaims = Depends(valiss_message)``. Raises 401 when the
    middleware did not run."""
    from starlette.exceptions import HTTPException

    claims = getattr(request.state, _STATE_KEY, None)
    if claims is None:
        raise HTTPException(status_code=401, detail="valiss: missing message token")
    return claims
