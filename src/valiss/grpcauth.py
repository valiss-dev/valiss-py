"""gRPC client side of the valiss authentication scheme: call credentials
that attach the creds' tokens and, when the creds hold a seed, a fresh
per-call signature. ``Ext`` is the gRPC transport extension claim Go
servers enforce; mint it into tokens with
``token.issue_user(..., extensions=[Ext(...)])``.

Requires the ``grpc`` extra (grpcio).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import grpc

from . import creds, token
from .errors import ValissError


@dataclass
class Ext:
    """gRPC transport extension claim: binds a token to specific methods.

    Enforcement on the Go server is fail-closed: every token in the chain
    must carry the extension (unless the Authenticator allows missing
    ones), an empty methods list grants nothing, and allow-all is the
    explicit wildcard ``Ext(methods=["*"])``.
    """

    # methods allowed, as gRPC full method names, e.g.
    # "/example.v1.WidgetService/CreateWidget". A trailing "*" is a prefix
    # wildcard: "/example.v1.WidgetService/*" covers the whole service and
    # "*" covers everything. Empty grants nothing.
    methods: list[str] = field(default_factory=list)

    def extension_name(self) -> str:
        return "grpc"

    def extension_payload(self) -> Mapping[str, Any]:
        return {"methods": self.methods} if self.methods else {}


class _CredentialsPlugin(grpc.AuthMetadataPlugin):
    """Attaches the creds' tokens and, when the creds hold a seed, a fresh
    per-call signature."""

    def __init__(self, c: creds.Creds, now: Callable[[], datetime] | None):
        self._account_token = c.account_token
        self._user_token = c.user_token
        self._signer = c.signer()
        self._now = now

    def __call__(
        self,
        context: grpc.AuthMetadataContext,
        callback: grpc.AuthMetadataPluginCallback,
    ) -> None:
        try:
            md: list[tuple[str, str]] = []
            if self._account_token:
                md.append((token.HEADER_ACCOUNT_TOKEN, self._account_token))
            if self._user_token:
                md.append((token.HEADER_USER_TOKEN, self._user_token))
            if self._signer is not None:
                timestamp, signature = token.sign_request(
                    self._signer, self._now() if self._now is not None else None
                )
                md.append((token.HEADER_TIMESTAMP, timestamp))
                md.append((token.HEADER_SIGNATURE, signature))
        except ValissError as exc:
            callback((), exc)
            return
        callback(tuple(md), None)


def call_credentials(
    c: creds.Creds, *, now: Callable[[], datetime] | None = None
) -> grpc.CallCredentials:
    """Client call credentials from creds: the account token, the optional
    user token, and per-call signatures from the seed (absent for bearer
    creds).

    gRPC sends call credentials only over secure channels; for local
    plaintext-equivalent transports compose with
    ``grpc.local_channel_credentials()``:

        channel_creds = grpc.composite_channel_credentials(
            grpc.ssl_channel_credentials(), call_credentials(creds_))
        channel = grpc.secure_channel(addr, channel_creds)
    """
    c.signer()  # fail fast on a malformed seed
    return grpc.metadata_call_credentials(_CredentialsPlugin(c, now), name="valiss")
