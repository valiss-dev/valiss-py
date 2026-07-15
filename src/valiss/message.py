"""Message tokens: per-message proofs of origin, the optional fourth chain
level of the valiss scheme.

A user key mints a short-lived, self-signed token (``iss == sub``) that binds
a message to a destination (``audience``) and a payload checksum, and may
embed the emitter's provenance chain — the operator-signed account token and
the account-signed user token — so a receiver verifies it offline with only
the operator public key. Message tokens are proofs, never credentials:
possession grants nothing, and the request verifier never accepts one.

``verify_message`` walks the chain operator → account → user → message,
requires every level to agree on the epoch, checks each validity window at
the verification instant, and enforces the audience and checksum bindings the
caller requests. It mirrors the Go ``VerifyMessage`` (valiss.dev/valiss,
``message.go``) byte for byte and reason for reason.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from . import nkeys, token
from .errors import Reason, ValissError

# The validity window the contrib transports mint message tokens with: long
# enough for delivery latency and clock drift, short enough to bound capture
# exposure.
DEFAULT_MESSAGE_TTL = timedelta(seconds=30)


@dataclass
class MessageClaims(token.Claims):
    """Verified content of a message token, together with the chain identities
    it was checked against. A message token is a proof, not a credential."""

    # audience is the destination the token was minted for (aud); empty when
    # the token is unbound.
    audience: str = ""
    # checksum is the lowercase-hex SHA-256 of the payload the token was minted
    # over; empty when the token carries no payload binding.
    checksum: str = ""
    # epoch is the trust-domain epoch the token was issued in.
    epoch: int = 0
    # ext carries the named extension claims, decoded from JSON.
    ext: dict[str, Any] = field(default_factory=dict)
    # account is the verified tenant identity from the chain.
    account: token.AccountClaims | None = None
    # user is the verified emitter identity from the chain; its subject key
    # signed the message token.
    user: token.UserClaims | None = None
    # operator is the trust domain the message verified under, when an operator
    # policy was supplied; None otherwise.
    operator: token.OperatorClaims | None = None


def checksum(payload: bytes) -> str:
    """Lowercase-hex SHA-256 of a payload exactly as delivered: the value a
    message token embeds and a receiver compares against."""
    return hashlib.sha256(payload).hexdigest()


def _is_hex_sha256(s: str) -> bool:
    return len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def _check_chain(account_token: str, user_token: str, emitter_pub: str) -> None:
    """Fail a mint fast when the embedded chain is structurally broken. No
    trust anchor is available at mint time, so the account token is only
    checked for self-consistency; verify_message roots it in the operator
    key."""
    issuer = token.issuer_of(account_token)
    account = token.verify_account(account_token, issuer)
    user = token.verify_user(user_token, account.subject)
    if user.subject != emitter_pub:
        raise ValissError("valiss: chain user token is not for the minting user key")


def issue_message(
    user: nkeys.KeyPair,
    *,
    audience: str = "",
    checksum: str = "",  # noqa: A002 - matches the wire claim name
    chain: tuple[str, str] | None = None,
    epoch: int = 0,
    ttl: timedelta | None = None,
    expiry: datetime | None = None,
    not_before: datetime | None = None,
    extensions: Iterable[token.Extension] = (),
    now: datetime | None = None,
) -> str:
    """Mint a per-message proof of origin signed by the emitter's user key over
    itself (``iss == sub``). ``audience`` binds it to a destination,
    ``checksum`` (the lowercase-hex SHA-256 of the payload) to the bytes, and
    ``chain=(account_token, user_token)`` embeds the provenance chain so a
    receiver verifies offline with only the operator public key. Message tokens
    must carry an expiry (``ttl`` or ``expiry``): they are short-lived proofs.
    """
    if not nkeys.is_valid_public_user_key(user.public_key):
        raise ValissError(
            "valiss: message tokens must be signed by a user-type nkey (expected an SU... seed)"
        )
    now = now or token._now()
    # Validate the option-carried claims first (checksum shape, extension
    # names), matching Go's order where option errors surface before the
    # expiry check.
    if checksum and not _is_hex_sha256(checksum):
        raise ValissError("valiss: checksum must be the lowercase-hex SHA-256 of the payload")
    ext = token._extensions_claim(extensions)
    expires, nbf = token._validity(ttl, expiry, not_before, now)
    if not expires:
        raise ValissError("valiss: message tokens must carry an expiry (ttl or expiry)")
    body: dict[str, Any] = {"type": token._MESSAGE_TYPE}
    if epoch:
        body["epoch"] = epoch
    if checksum:
        body["checksum"] = checksum
    if chain is not None:
        account_token, user_token = chain
        _check_chain(account_token, user_token, user.public_key)
        ch: dict[str, Any] = {}
        if account_token:
            ch["account"] = account_token
        if user_token:
            ch["user"] = user_token
        body["chain"] = ch
    if ext:
        body["ext"] = ext
    return token._encode_v1(
        user, body, subject=user.public_key, audience=audience,
        expires=expires, not_before=nbf, now=now,
    )


def verify_message(
    tok: str,
    operator_pub_key: str,
    *,
    now: datetime | None = None,
    skew: timedelta = token.DEFAULT_SKEW,
    audience: str | None = None,
    require_checksum: bool = False,
    payload: bytes | None = None,
    chain: tuple[str, str] | None = None,
    operator_token: str | None = None,
) -> MessageClaims:
    """Verify a per-message proof of origin against the pinned operator public
    key: walk the chain operator → account → user → message, require all levels
    to agree on the epoch, check every validity window at the verification
    instant (``now``; default now), and enforce the bindings requested.

    ``audience`` requires the token be bound to exactly that destination (a
    token bound elsewhere, or to nothing, is rejected). ``payload`` requires the
    token's checksum to match the bytes; ``require_checksum`` insists a checksum
    is present without comparing bytes. ``chain=(account_token, user_token)``
    supplies the provenance chain out of band for a token minted without one; a
    token that embeds a chain must embed this exact chain. ``operator_token``
    enforces the trust domain's operator policy (window and epoch).

    A verified message token proves origin only. It is not a credential.
    """
    d = token._decode_token(tok)
    if d.type != token._MESSAGE_TYPE:
        raise ValissError(f"valiss: not a message token (type {d.type!r})", reason=Reason.WRONG_TYPE)
    if d.issuer != d.subject:
        raise ValissError(
            "valiss: message token not self-signed by its user key", reason=Reason.WRONG_ISSUER
        )
    if not nkeys.is_valid_public_user_key(d.subject):
        raise ValissError(
            "valiss: message token subject is not a user public key",
            reason=Reason.WRONG_SUBJECT_ROLE,
        )

    embedded = d.chain
    supplied = {"account": chain[0], "user": chain[1]} if chain is not None else None
    if embedded is None and supplied is None:
        raise ValissError(
            "valiss: message token carries no chain and none was supplied", reason=Reason.NO_CHAIN
        )
    if embedded is None:
        use = supplied
    elif supplied is not None and (
        supplied["account"] != (embedded.get("account") or "")
        or supplied["user"] != (embedded.get("user") or "")
    ):
        raise ValissError(
            "valiss: message token embeds a chain that differs from the supplied chain",
            reason=Reason.CHAIN_MISMATCH,
        )
    else:
        use = embedded
    assert use is not None  # exhausted above
    chain_account = use.get("account") or ""
    chain_user = use.get("user") or ""

    at = now or token._now()

    # Anchor: verify the chain's account token against the pinned operator key,
    # then the emitter's user token against the account. VerifyAccount/User
    # raise the same reason codes they would at top level.
    account = token.verify_account(chain_account, operator_pub_key)
    # Go keys operator enforcement on the presence of the option, not its value,
    # so an operator token is verified whenever one is supplied.
    operator = (
        token.verify_operator(operator_token, operator_pub_key)
        if operator_token is not None
        else None
    )

    user = token.verify_user(chain_user, account.subject)
    if user.subject != d.issuer:
        raise ValissError(
            "valiss: message token not signed by the chain's user key",
            reason=Reason.CHAIN_USER_MISMATCH,
        )

    if operator is not None:
        if operator.expired(at, skew):
            raise ValissError(
                "valiss: operator token expired: the trust domain is closed", reason=Reason.EXPIRED
            )
        if operator.not_yet_valid(at, skew):
            raise ValissError("valiss: operator token not yet valid", reason=Reason.NOT_YET_VALID)
        if d.epoch != operator.epoch:
            raise ValissError(
                f"valiss: message token epoch {d.epoch}, trust domain epoch {operator.epoch}",
                reason=Reason.EPOCH_MISMATCH,
            )
    if d.epoch != account.epoch:
        raise ValissError(
            f"valiss: message token epoch {d.epoch}, account token epoch {account.epoch}",
            reason=Reason.EPOCH_MISMATCH,
        )
    if d.epoch != user.epoch:
        raise ValissError(
            f"valiss: message token epoch {d.epoch}, user token epoch {user.epoch}",
            reason=Reason.EPOCH_MISMATCH,
        )

    claims = MessageClaims(
        **vars(token._claims_of(d)),
        audience=d.audience,
        checksum=d.checksum,
        epoch=d.epoch,
        ext=d.ext,
        account=account,
        user=user,
        operator=operator,
    )

    if account.expired(at, skew):
        raise ValissError("valiss: account token expired", reason=Reason.EXPIRED)
    if account.not_yet_valid(at, skew):
        raise ValissError("valiss: account token not yet valid", reason=Reason.NOT_YET_VALID)
    if user.expired(at, skew):
        raise ValissError("valiss: user token expired", reason=Reason.EXPIRED)
    if user.not_yet_valid(at, skew):
        raise ValissError("valiss: user token not yet valid", reason=Reason.NOT_YET_VALID)
    if claims.expired(at, skew):
        raise ValissError("valiss: message token expired", reason=Reason.EXPIRED)
    if claims.not_yet_valid(at, skew):
        raise ValissError("valiss: message token not yet valid", reason=Reason.NOT_YET_VALID)

    # An empty audience is a no-op, matching Go's `cfg.audience != ""` guard.
    if audience and claims.audience != audience:
        raise ValissError(
            f"valiss: message token audience {claims.audience!r}, expected {audience!r}",
            reason=Reason.WRONG_AUDIENCE,
        )

    if payload is not None:
        if not claims.checksum:
            raise ValissError("valiss: message token carries no checksum", reason=Reason.CHECKSUM_MISSING)
        if claims.checksum != checksum(payload):
            raise ValissError("valiss: payload checksum mismatch", reason=Reason.CHECKSUM_MISMATCH)
    elif require_checksum and not claims.checksum:
        raise ValissError("valiss: message token carries no checksum", reason=Reason.CHECKSUM_MISSING)

    return claims
