"""gRPC server interceptor for message tokens (proofs of origin).

:func:`unary_server_interceptor` requires every unary call to carry a
``valiss-message-token`` proving the origin of its exact request message at this
method, verified offline against the operator key with the audience pinned to the
full method and the checksum compared to the request's deterministic protobuf
encoding. It speaks the receiving side of chain negotiation via the
``valiss-chain: required`` trailer. Handlers read the verified claims with
:func:`message_from_context`.

A message token proves origin only — it authenticates the message, not a caller.
Pair with ``valiss.grpcauth`` when the caller must also authenticate. grpcsig
covers unary-request RPCs (there is one message to bind); handlers whose request
is a stream are passed through unverified.

Requires the ``grpcsig`` extra (grpcio + protobuf).
"""

from __future__ import annotations

import contextvars
from collections.abc import Iterator, Mapping
from typing import Any, Callable

import grpc

from .. import token
from .._msgtransport import Reject, authenticate_message, build_verifier
from ..chain import ChainCache
from ..keyring import Keyring
from ..message import MessageClaims

# The verified message claims for the call currently on this thread.
_MESSAGE: contextvars.ContextVar[MessageClaims] = contextvars.ContextVar("valiss_message")


def message_from_context() -> MessageClaims | None:
    """The verified message claims of the call being handled on this thread, or
    ``None`` outside a grpcsig-verified handler."""
    return _MESSAGE.get(None)


def _incoming(metadata: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in metadata:
        if key not in out:
            out[key] = value
    return out


class _ServerInterceptor(grpc.ServerInterceptor):
    def __init__(
        self,
        verify,
        verify_options: Mapping[str, Any],
        cache: ChainCache | None,
    ):
        self._verify = verify
        self._verify_opts = verify_options
        self._cache = cache

    def intercept_service(self, continuation, handler_call_details):
        handler = continuation(handler_call_details)
        if handler is None or handler.request_streaming:
            # Message tokens bind a single request message; a request stream has
            # no one message to check, so pass it through unverified.
            return handler
        return self._wrap(handler, handler_call_details.method)

    def _authenticate(self, request: object, context: grpc.ServicerContext, method: str) -> MessageClaims:
        md = _incoming(context.invocation_metadata())
        tok = md.get(token.HEADER_MESSAGE_TOKEN, "")
        if not tok:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "valiss: missing message token")
        from .payload import payload

        try:
            body = payload(request)
        except Exception as exc:  # noqa: BLE001 - a non-proto message is an auth failure
            context.abort(grpc.StatusCode.UNAUTHENTICATED, str(exc))
        result = authenticate_message(
            self._verify,
            self._verify_opts,
            self._cache,
            token_str=tok,
            body=body,
            audience_str=method,
            chain_account=md.get(token.HEADER_CHAIN_ACCOUNT_TOKEN, ""),
            chain_user=md.get(token.HEADER_CHAIN_USER_TOKEN, ""),
        )
        if isinstance(result, Reject):
            if result.chain_required:
                context.set_trailing_metadata([(token.HEADER_CHAIN, token.CHAIN_REQUIRED)])
            context.abort(grpc.StatusCode.UNAUTHENTICATED, result.message)
        return result

    def _wrap(self, handler: grpc.RpcMethodHandler, method: str) -> grpc.RpcMethodHandler:
        authenticate = self._authenticate

        if not handler.response_streaming:

            def unary(request: object, context: grpc.ServicerContext) -> Any:
                reset = _MESSAGE.set(authenticate(request, context, method))
                try:
                    return handler.unary_unary(request, context)
                finally:
                    _MESSAGE.reset(reset)

            return grpc.unary_unary_rpc_method_handler(
                unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        def stream(request: object, context: grpc.ServicerContext) -> Iterator[Any]:
            reset = _MESSAGE.set(authenticate(request, context, method))
            try:
                yield from handler.unary_stream(request, context)
            finally:
                _MESSAGE.reset(reset)

        return grpc.unary_stream_rpc_method_handler(
            stream,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )


def unary_server_interceptor(
    operator_pub_key: str | None = None,
    *,
    keyring: Keyring | None = None,
    chain_cache: ChainCache | None = None,
    verify_options: Mapping[str, Any] | None = None,
) -> grpc.ServerInterceptor:
    """A server interceptor verifying a message token on every unary call. Give
    exactly one trust anchor: ``operator_pub_key`` (single operator) or
    ``keyring`` (several). ``chain_cache`` remembers negotiated chains so an
    emitter pays the chain retransmit once, not per call; ``verify_options``
    passes extra keyword bindings to every ``verify_message`` call (e.g.
    ``operator_token=`` to enforce the domain epoch, or ``chain=`` to pin an
    emitter's chain in configuration). Pass it in ``grpc.server(...,
    interceptors=[…])``."""
    verify, opts = build_verifier(operator_pub_key, keyring, verify_options)
    return _ServerInterceptor(verify, opts, chain_cache)
