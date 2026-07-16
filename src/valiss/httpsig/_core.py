# pyright: strict
"""HTTP-specific glue for the message-token transport: the canonical audience
bytes. The transport-agnostic minter, trust-anchor binding, and
verify-with-negotiation state machine live in :mod:`valiss._msgtransport` and are
re-exported here for the httpsig client and middleware.
"""

from __future__ import annotations

from .._msgtransport import Reject, VerifyMessage, authenticate_message, build_verifier, minter

__all__ = [
    "Reject",
    "VerifyMessage",
    "audience",
    "authenticate_message",
    "build_verifier",
    "minter",
]


def audience(host: str, path: str) -> str:
    """Canonical destination identity an HTTP message token is bound to: host and
    path, query and scheme excluded (the scheme is unknowable behind a TLS
    terminator). The emitting client derives it from the request URL's host and
    path, the receiving middleware from the Host header and path — identical
    bytes."""
    return host + path
