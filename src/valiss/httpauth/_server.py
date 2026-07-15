# pyright: strict
"""Framework-agnostic core of the HTTP server middleware: turn the valiss
request material into a verified Identity, or a (status, message) rejection the
adapter renders. Shared by the Django and ASGI middleware."""

from __future__ import annotations

from ..errors import ValissError
from ..verifier import Identity, Request, Verifier
from .extension import authorize_ext, request_context


def authenticate(
    verifier: Verifier,
    *,
    account_token: str,
    user_token: str,
    timestamp: str,
    signature: str,
    nonce: str,
    method: str,
    host: str,
    path: str,
    allow_missing: bool,
) -> Identity | tuple[int, str]:
    """Verify a request and enforce its http extension. Returns the
    :class:`Identity` on success, or ``(status, message)`` — 401 for an
    authentication failure, 403 for an extension denial — on rejection."""
    if not account_token and not user_token:
        return (401, "valiss: missing credentials")
    request = Request(
        account_token=account_token,
        user_token=user_token,
        timestamp=timestamp,
        signature=signature,
        context=request_context(method, host, path, nonce),
        nonce=nonce,
    )
    try:
        identity = verifier.verify(request)
    except ValissError as exc:
        return (401, str(exc))
    try:
        authorize_ext(identity, method, host, path, allow_missing=allow_missing)
    except ValissError as exc:
        return (403, str(exc))
    return identity
