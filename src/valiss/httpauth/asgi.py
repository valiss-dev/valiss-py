"""Pure-ASGI server middleware for the valiss scheme — works with any ASGI app
(Starlette, FastAPI, Quart, …).

:class:`Middleware` wraps an ASGI app: every HTTP request is authenticated
against the verifier and its http extension enforced before the app runs. The
verified :class:`~valiss.verifier.Identity` is stored on the request state
(``request.state.valiss_identity``); read it with :func:`identity`, or in
FastAPI inject it with ``Depends(valiss_identity)``. Unauthenticated requests
get 401, requests outside an extension's bounds 403 — the app never sees them.

    from fastapi import Depends, FastAPI
    from valiss.httpauth.asgi import Middleware, valiss_identity
    from valiss import Verifier, ALLOW_ALL, Identity

    app = FastAPI()
    app.add_middleware(Middleware, verifier=Verifier(OPERATOR_PUB_KEY, ALLOW_ALL))

    @app.get("/whoami")
    def whoami(id: Identity = Depends(valiss_identity)):
        return {"tenant": id.account.name}

Requires the ``fastapi`` extra (which pulls in Starlette; FastAPI itself is only
needed for the ``Depends`` accessor).
"""

from __future__ import annotations

from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ..verifier import Identity, Verifier
from ._server import authenticate

# The scope-state key under which the verified identity is stashed; also the
# attribute name on ``request.state``.
_STATE_KEY = "valiss_identity"


class Middleware:
    """ASGI middleware that authenticates every HTTP request against the
    verifier and enforces the tokens' http extensions, fail-closed: tokens
    without the extension are denied unless ``allow_missing_extension`` is set.

    Add it with ``app.add_middleware(Middleware, verifier=…)`` (Starlette /
    FastAPI) or wrap any ASGI app directly as ``Middleware(app, verifier=…)``.
    """

    def __init__(
        self, app: ASGIApp, verifier: Verifier, *, allow_missing_extension: bool = False
    ) -> None:
        self.app = app
        self.verifier = verifier
        self.allow_missing = allow_missing_extension

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # ASGI lower-cases header names; decode as latin-1 (the HTTP header
        # charset). valiss tokens are ASCII base64url, so this is lossless.
        headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in scope["headers"]}
        result = authenticate(
            self.verifier,
            account_token=headers.get("valiss-account-token", ""),
            user_token=headers.get("valiss-user-token", ""),
            timestamp=headers.get("valiss-timestamp", ""),
            signature=headers.get("valiss-signature", ""),
            nonce=headers.get("valiss-nonce", ""),
            method=scope["method"],
            # The Host header is what the client signed and what the extension
            # matches.
            host=headers.get("host", ""),
            path=scope["path"],
            allow_missing=self.allow_missing,
        )
        if isinstance(result, tuple):
            status, message = result
            await _reject(send, status, message)
            return

        # scope["state"] is the per-request state Starlette's Request.state
        # reads; create it if an outer middleware has not. Downstream sees the
        # same scope dict, so the mutation is visible to the app.
        scope.setdefault("state", {})[_STATE_KEY] = result
        await self.app(scope, receive, send)


async def _reject(send: Send, status: int, message: str) -> None:
    body = message.encode("utf-8")
    start: Message = {
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"text/plain; charset=utf-8"),
            (b"content-length", str(len(body)).encode("ascii")),
        ],
    }
    await send(start)
    await send({"type": "http.response.body", "body": body})


def identity(request: Request) -> Identity | None:
    """The verified identity the middleware stored on the request state, or
    ``None`` when the middleware did not run (e.g. it is not installed)."""
    return getattr(request.state, _STATE_KEY, None)


def valiss_identity(request: Request) -> Identity:
    """FastAPI dependency yielding the verified identity: use as
    ``id: Identity = Depends(valiss_identity)``. Raises 401 when the middleware
    did not run — with the middleware installed the request is already verified,
    so this only fires when it is missing."""
    from starlette.exceptions import HTTPException

    id = getattr(request.state, _STATE_KEY, None)
    if id is None:
        raise HTTPException(status_code=401, detail="valiss: authentication required")
    return id
