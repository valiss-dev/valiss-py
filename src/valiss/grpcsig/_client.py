"""gRPC client interceptor for message tokens: mint a fresh proof of origin per
unary call and speak the sending side of chain negotiation.

Requires the ``grpcsig`` extra (grpcio + protobuf).
"""

from __future__ import annotations

from collections import namedtuple
from collections.abc import Callable
from datetime import datetime, timedelta

import grpc

from .. import creds, token
from .._msgtransport import minter
from ..message import DEFAULT_MESSAGE_TTL, checksum, issue_message
from .payload import payload


class _ClientCallDetails(
    namedtuple(
        "_ClientCallDetails",
        ["method", "timeout", "metadata", "credentials", "wait_for_ready", "compression"],
    ),
    grpc.ClientCallDetails,
):
    """A mutable-by-copy view of a call's details, so the interceptor can add the
    message-token metadata without touching the caller's."""


def _with_metadata(
    details: grpc.ClientCallDetails, extra: list[tuple[str, str]]
) -> _ClientCallDetails:
    metadata = list(details.metadata or []) + extra
    return _ClientCallDetails(
        details.method,
        details.timeout,
        metadata,
        details.credentials,
        getattr(details, "wait_for_ready", None),
        getattr(details, "compression", None),
    )


def _trailer(call: grpc.Call, key: str) -> str:
    for k, v in call.trailing_metadata() or ():
        if k == key:
            return v
    return ""


class _ClientInterceptor(grpc.UnaryUnaryClientInterceptor):
    def __init__(
        self,
        c: creds.Creds,
        ttl: timedelta | None,
        negotiate: bool,
        now: Callable[[], datetime] | None,
    ):
        self._user, self._epoch = minter(c)
        self._account_token = c.account_token
        self._user_token = c.user_token
        self._ttl = ttl if ttl is not None else DEFAULT_MESSAGE_TTL
        self._negotiate = negotiate
        self._now = now

    def _mint(self, method: str, request: object) -> str:
        chain = None if self._negotiate else (self._account_token, self._user_token)
        return issue_message(
            self._user,
            audience=method,
            checksum=checksum(payload(request)),
            ttl=self._ttl,
            epoch=self._epoch,
            chain=chain,
            now=self._now() if self._now is not None else None,
        )

    def intercept_unary_unary(self, continuation, client_call_details, request):
        tok = self._mint(client_call_details.method, request)
        signed = _with_metadata(client_call_details, [(token.HEADER_MESSAGE_TOKEN, tok)])
        call = continuation(signed, request)
        if not self._negotiate:
            return call
        if (
            call.code() == grpc.StatusCode.UNAUTHENTICATED
            and _trailer(call, token.HEADER_CHAIN) == token.CHAIN_REQUIRED
        ):
            # The server does not know our chain: retry once with the chain
            # detached alongside the same still-valid token.
            retry = _with_metadata(
                client_call_details,
                [
                    (token.HEADER_MESSAGE_TOKEN, tok),
                    (token.HEADER_CHAIN_ACCOUNT_TOKEN, self._account_token),
                    (token.HEADER_CHAIN_USER_TOKEN, self._user_token),
                ],
            )
            return continuation(retry, request)
        return call


def unary_client_interceptor(
    c: creds.Creds,
    *,
    ttl: timedelta | None = None,
    negotiate: bool = False,
    now: Callable[[], datetime] | None = None,
) -> grpc.UnaryUnaryClientInterceptor:
    """A client interceptor that mints a fresh message token per unary call — a
    proof of origin bound to the full method and the request message's
    deterministic protobuf bytes, carried in ``valiss-message-token`` metadata.
    Apply with ``grpc.intercept_channel(channel, unary_client_interceptor(creds))``.

    Build it from bundle creds (account token + user token + seed). ``ttl``
    overrides the default message-token window. ``negotiate=True`` sends chainless
    tokens and retries once with the chain in detached metadata when the server
    answers the ``valiss-chain: required`` trailer — against a server with a chain
    cache the steady state is the bare token per call.
    """
    return _ClientInterceptor(c, ttl, negotiate, now)
