# pyright: strict
"""Framework-agnostic core of the message-token (proof-of-origin) HTTP
transport: the canonical audience bytes, the emitter-creds minter, and the
receiver's verify-with-chain-negotiation state machine. Pure logic — no httpx or
framework dependency — shared by the client transport and the Django/ASGI
middleware.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .. import creds, message, nkeys, token
from ..chain import ChainCache
from ..errors import Reason, ValissError
from ..keyring import Keyring
from ..message import MessageClaims

# A verify function bound to its trust anchor: verify_message with the operator
# key or keyring already applied, taking the token plus keyword bindings.
VerifyMessage = Callable[..., MessageClaims]


def audience(host: str, path: str) -> str:
    """Canonical destination identity a message token is bound to: host and path,
    query and scheme excluded (the scheme is unknowable behind a TLS terminator).
    The emitting client and the receiving middleware must derive identical bytes —
    the client from the request URL's host and path, the server from the Host
    header and path."""
    return host + path


def minter(c: creds.Creds) -> tuple[nkeys.KeyPair, int]:
    """Validate emitter bundle creds and derive the mint parameters: the user
    keypair from the seed and the trust-domain epoch from the chain tokens, which
    must agree on it (verify_message requires every level to). The seed's key
    *role* is enforced per request by :func:`~valiss.message.issue_message`, not
    here — a non-user seed mints nothing but constructs fine."""
    if not c.account_token or not c.user_token or not c.seed:
        raise ValissError(
            "valiss: message signing requires bundle creds: account token, user token, and seed"
        )
    try:
        user = nkeys.from_seed(c.seed)
    except ValissError as exc:
        raise ValissError(f"valiss: creds seed: {exc}") from exc
    try:
        account = token.verify_account(c.account_token, token.issuer_of(c.account_token))
    except ValissError as exc:
        raise ValissError(f"valiss: creds account token: {exc}") from exc
    try:
        user_claims = token.verify_user(c.user_token, account.subject)
    except ValissError as exc:
        raise ValissError(f"valiss: creds user token: {exc}") from exc
    if account.epoch != user_claims.epoch:
        raise ValissError(
            f"valiss: creds chain epochs disagree: account {account.epoch}, user {user_claims.epoch}"
        )
    return user, user_claims.epoch


def build_verifier(
    operator_pub_key: str | None,
    keyring: Keyring | None,
    verify_options: Mapping[str, Any] | None,
) -> tuple[VerifyMessage, dict[str, Any]]:
    """Bind the middleware's trust anchor into a verify function and return it
    with the static verify options. Exactly one of ``operator_pub_key`` or
    ``keyring`` must be given."""
    if (operator_pub_key is None) == (keyring is None):
        raise ValissError(
            "valiss: httpsig middleware requires exactly one of operator_pub_key or keyring"
        )
    if keyring is not None:

        def verify(tok: str, **kw: Any) -> MessageClaims:
            return message.verify_message(tok, keyring=keyring, **kw)

    else:
        assert operator_pub_key is not None

        def verify(tok: str, **kw: Any) -> MessageClaims:
            return message.verify_message(tok, operator_pub_key, **kw)

    return verify, dict(verify_options or {})


@dataclass(frozen=True, slots=True)
class Reject:
    """A middleware rejection: the 401 body, and whether to attach the
    ``valiss-chain: required`` signal asking the client to retransmit its chain."""

    message: str
    chain_required: bool = False


def authenticate_message(
    verify: VerifyMessage,
    verify_options: Mapping[str, Any],
    cache: ChainCache | None,
    *,
    token_str: str,
    body: bytes,
    audience_str: str,
    chain_account: str,
    chain_user: str,
) -> MessageClaims | Reject:
    """Verify a message token against its destination and body, speaking the
    receiving side of chain negotiation. Detached chain headers outrank the
    cache; a pinned chain in ``verify_options`` outranks both (applied last, it
    wins inside verify_message), and the audience/payload bindings are always
    enforced. Returns the verified claims or a :class:`Reject`.

    A chainless token whose chain is not otherwise known reduces to
    ``reason=no_chain`` and a chain-required rejection, asking the client to
    retransmit with the chain attached; a genuine failure (bad checksum, wrong
    audience, expiry) is a plain rejection with no negotiation signal. A cached
    chain that no longer verifies is attributed and evicted before rejecting."""
    detached = bool(chain_account and chain_user)
    cached = False
    cache_key = ""
    if not detached and cache is not None:
        try:
            cache_key = token.decode(token_str).issuer
        except ValissError:
            cache_key = ""
        if cache_key:
            entry = cache.get(cache_key)
            if entry is not None:
                chain_account, chain_user = entry
                cached = True

    def run(with_chain: bool) -> MessageClaims:
        opts: dict[str, Any] = {}
        if with_chain:
            opts["chain"] = (chain_account, chain_user)
        opts.update(verify_options)  # a pinned chain / operator policy wins
        opts["audience"] = audience_str  # always enforced, never weakened
        opts["payload"] = body
        return verify(token_str, **opts)

    try:
        claims = run(detached or cached)
    except ValissError as exc:
        if cached:
            assert cache is not None  # cached is only set when cache is present
            # Attribute the failure before evicting: without the cached chain a
            # self-contained token settles on its own, and only a chainless token
            # leaves the cached entry as the suspect.
            try:
                claims = run(False)
            except ValissError as exc2:
                if exc2.reason == Reason.NO_CHAIN:
                    cache.delete(cache_key)  # cache is not None on the cached path
                    return Reject("valiss: message token chain required", chain_required=True)
                return Reject(str(exc2))
            else:
                # A self-contained token verified on its own; the cached chain
                # was stale (or irrelevant), so drop it. detached is false on the
                # cached path, so there is nothing to re-cache.
                cache.delete(cache_key)
                return claims
        if exc.reason == Reason.NO_CHAIN:
            return Reject("valiss: message token chain required", chain_required=True)
        return Reject(str(exc))

    if detached and cache is not None:
        cache.put(claims.subject, chain_account, chain_user)
    return claims
