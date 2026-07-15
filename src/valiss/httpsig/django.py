"""Django server middleware for message tokens (proofs of origin).

``middleware(operator_pub_key)`` returns a Django middleware factory that
requires every request to carry a ``valiss-message-token`` proving the origin of
its exact body at this destination, verified offline against the operator key.
The verified claims are attached as ``request.valiss_message`` (read them with
:func:`message_claims`). A missing or invalid token gets 401; a chainless token
whose chain is unknown gets the ``valiss-chain: required`` negotiation signal.

A message token proves origin only — it authenticates the message, not a caller.
Pair with ``valiss.httpauth`` when the caller must also authenticate.

Requires the ``django`` extra.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from django.http import HttpRequest, HttpResponse

from ..chain import ChainCache
from ..keyring import Keyring
from ..message import MessageClaims
from .. import token as token_mod
from ._core import Reject, audience, authenticate_message, build_verifier

GetResponse = Callable[[HttpRequest], HttpResponse]


def middleware(
    operator_pub_key: str | None = None,
    *,
    keyring: Keyring | None = None,
    chain_cache: ChainCache | None = None,
    verify_options: Mapping[str, Any] | None = None,
) -> Callable[[GetResponse], GetResponse]:
    """Build a Django middleware verifying a message token on every request.
    Give exactly one trust anchor: ``operator_pub_key`` (single operator) or
    ``keyring`` (several). ``chain_cache`` remembers negotiated chains so an
    emitter pays the chain retransmit once, not per message; ``verify_options``
    passes extra keyword bindings to every ``verify_message`` call (e.g.
    ``operator_token=`` to enforce the domain epoch, or ``chain=`` to pin an
    emitter's chain in configuration)."""
    verify, verify_opts = build_verifier(operator_pub_key, keyring, verify_options)

    def make(get_response: GetResponse) -> GetResponse:
        def process(request: HttpRequest) -> HttpResponse:
            headers = request.headers
            tok = headers.get("valiss-message-token", "")
            if not tok:
                return HttpResponse(
                    "valiss: missing message token", status=401, content_type="text/plain; charset=utf-8"
                )
            # request.body buffers the payload; the view can still read it.
            result = authenticate_message(
                verify,
                verify_opts,
                chain_cache,
                token_str=tok,
                body=request.body,
                audience_str=audience(headers.get("host", ""), request.path),
                chain_account=headers.get("valiss-chain-account-token", ""),
                chain_user=headers.get("valiss-chain-user-token", ""),
            )
            if isinstance(result, Reject):
                resp = HttpResponse(result.message, status=401, content_type="text/plain; charset=utf-8")
                if result.chain_required:
                    resp[token_mod.HEADER_CHAIN] = token_mod.CHAIN_REQUIRED
                return resp
            request.valiss_message = result  # type: ignore[attr-defined]
            return get_response(request)

        return process

    return make


def message_claims(request: HttpRequest) -> MessageClaims | None:
    """The verified message claims the middleware attached, or ``None`` when it
    did not run for this request."""
    return getattr(request, "valiss_message", None)
