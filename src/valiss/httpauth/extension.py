# pyright: strict
"""The HTTP transport extension claim (``Ext``), its fail-closed authorization,
and the canonical request-context bytes shared by client and server.

Pure logic — no framework or httpx dependency — so it is importable with only
``cryptography``. The Django and ASGI middleware build on it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Self

from .. import token
from ..errors import Reason, ValissError
from ..verifier import Identity


@dataclass
class Ext:
    """HTTP transport extension claim: binds a token to specific hosts,
    methods, and paths. Mint it with ``token.issue_*(..., extensions=[Ext(...)])``.

    Enforcement is fail-closed at the extension level: every token in the chain
    must carry the extension (unless the middleware allows missing ones), and
    the zero-value extension grants nothing. The three dimensions are
    independent AND-filters, each constraining only when populated: a dimension
    left empty imposes no restriction on that dimension. So ``Ext(paths=["/v1/*"])``
    permits any host and method under ``/v1/``; scope a read-only surface by
    naming every dimension (``Ext(methods=["GET"], paths=["/admin/*"])``).
    Allow-all within a dimension is the explicit wildcard, e.g. ``paths=["*"]``.
    """

    # hosts allowed, matched exactly against the request Host. Empty: no host constraint.
    hosts: list[str] = field(default_factory=list[str])
    # methods allowed, matched exactly (upper-case, e.g. "GET"). Empty: every verb.
    methods: list[str] = field(default_factory=list[str])
    # paths allowed; a trailing "*" is a prefix wildcard. Empty: no path constraint.
    paths: list[str] = field(default_factory=list[str])

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

    @classmethod
    def decode(cls, payload: Mapping[str, Any]) -> Self:
        # ext_of has already guaranteed payload is an object; each dimension is
        # coerced to a string list so a malformed inner value fails loudly.
        return cls(
            hosts=[str(h) for h in payload.get("hosts") or ()],
            methods=[str(m) for m in payload.get("methods") or ()],
            paths=[str(p) for p in payload.get("paths") or ()],
        )

    def authorizes(self, method: str, host: str, path: str) -> bool:
        """Whether the extension permits the request. The zero value permits
        nothing; each populated dimension must match (host/method exactly,
        paths honoring the trailing-``*`` wildcard)."""
        if not self.hosts and not self.methods and not self.paths:
            return False
        if self.hosts and host not in self.hosts:
            return False
        if self.methods and method not in self.methods:
            return False
        if self.paths and not token.covered(self.paths, path):
            return False
        return True


def request_context(method: str, host: str, path: str, nonce: str = "") -> bytes:
    """Canonical request-context bytes the signature is bound to: method, host,
    path, and the per-request nonce. Client and server must derive identical
    bytes — the host is the request Host, the query is excluded, and method and
    path are matched exactly. The nonce is empty when replay suppression is off."""
    return f"http\n{method}\n{host}\n{path}\n{nonce}".encode()


def authorize_ext(
    identity: Identity, method: str, host: str, path: str, *, allow_missing: bool = False
) -> None:
    """Enforce the HTTP extensions a verified request's tokens carry (account,
    then user — AND, so an account extension clamps its users). Every token must
    carry the extension and permit the request; with ``allow_missing`` a token
    without the extension imposes no constraint. Raises :class:`ValissError` (the
    transport maps it to 403)."""
    exts = [identity.account.ext]
    if identity.user is not None:
        exts.append(identity.user.ext)
    for ext in exts:
        decoded = token.ext_of(ext, Ext)  # raises extension_invalid on a malformed payload
        if decoded is None:
            if allow_missing:
                continue
            raise ValissError(
                "valiss: token carries no http extension", reason=Reason.EXTENSION_INVALID
            )
        if not decoded.authorizes(method, host, path):
            raise ValissError(
                f"valiss: token does not permit {method} {path}", reason=Reason.EXTENSION_INVALID
            )
