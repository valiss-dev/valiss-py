"""Core of the valiss tenant authentication scheme.

Wire-compatible Python port of github.com/mikluko/valiss, scoped to the
client side: minting tokens and signing requests. Chain verification with
allowlists, epoch policy, and extension enforcement stays with the Go
server; the ``verify_*`` functions here check a single token's signature,
type, and issuer for tooling and tests.

The scheme is a three-level chain of Ed25519 nkeys:

- An operator holds an nkey; its public key is the trust anchor servers pin.
- The operator signs each tenant an account token bound to the tenant's own
  account nkey. Issued account tokens go in a server-side allowlist.
- A tenant delegates by signing user tokens with its account seed. A bearer
  user token authenticates by the token alone, without per-request
  signatures.
- The subject signs every request with its nkey over an RFC3339Nano
  timestamp bound to the transport's canonical request context (bearer
  tokens excepted), so a captured signature cannot authorize a different
  operation.

Tokens are nkey-signed JWTs (``ed25519-nkey`` algorithm); the ``valiss``
payload section carries the scheme's typed claim bodies. Authorization
rides named extension claims (``extensions=``): typed payloads the scheme
signs and transports but assigns no meaning. The httpauth and grpcauth
modules provide the transport extensions Go servers enforce.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from . import nkeys
from .errors import ValissError

# Header field names carrying the credential on each request. Used as gRPC
# metadata keys and HTTP header names alike.
HEADER_ACCOUNT_TOKEN = "valiss-account-token"
HEADER_USER_TOKEN = "valiss-user-token"
HEADER_TIMESTAMP = "valiss-timestamp"
HEADER_SIGNATURE = "valiss-signature"
HEADER_NONCE = "valiss-nonce"

# Bounds request-timestamp drift and token-expiry slack.
DEFAULT_SKEW = timedelta(minutes=2)

_TOKEN_HEADER = '{"typ":"JWT","alg":"ed25519-nkey"}'

_OPERATOR_TYPE = "operator"
_ACCOUNT_TYPE = "account"
_USER_TYPE = "user"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(encoded: str) -> bytes:
    pad = "=" * (-len(encoded) % 4)
    try:
        return base64.urlsafe_b64decode(encoded + pad)
    except (binascii.Error, ValueError) as exc:
        raise ValissError(f"valiss: bad token encoding: {exc}") from exc


def _rfc3339nano(ts: datetime) -> str:
    """Render like Go's time.RFC3339Nano: fraction trimmed of trailing zeros."""
    ts = ts.astimezone(timezone.utc)
    out = ts.strftime("%Y-%m-%dT%H:%M:%S")
    frac = f"{ts.microsecond:06d}".rstrip("0")
    if frac:
        out += f".{frac}"
    return out + "Z"


class Extension(Protocol):
    """A named claim payload carried in a token's ext field. The scheme
    signs and transports the payload untouched; meaning is assigned by
    whoever registered the name (httpauth.Ext, grpcauth.Ext, or the library
    consumer)."""

    def extension_name(self) -> str: ...

    def extension_payload(self) -> Mapping[str, Any]: ...


@dataclass
class RawExtension:
    """An extension claim given directly as a name and a JSON-serializable
    payload, for consumer-defined extensions without a dedicated type."""

    name: str
    payload: Mapping[str, Any]

    def extension_name(self) -> str:
        return self.name

    def extension_payload(self) -> Mapping[str, Any]:
        return self.payload


@dataclass
class Claims:
    """Verified RFC 7519 registered-claims content of a token."""

    # id is the token's unique identifier (jti), the allowlist key for
    # account tokens.
    id: str = ""
    # issuer is the public key that signed the token (iss).
    issuer: str = ""
    # subject is the subject's nkey public key (sub) that must sign requests.
    subject: str = ""
    # issued_at is the token mint time (iat).
    issued_at: datetime | None = None
    # expires_at is the token expiry (exp); None means the token never
    # expires.
    expires_at: datetime | None = None
    # not_before is the token activation time (nbf); None means immediately
    # valid.
    not_before: datetime | None = None

    def expired(self, now: datetime, skew: timedelta = DEFAULT_SKEW) -> bool:
        """Whether the token has passed its expiry (with skew slack)."""
        return self.expires_at is not None and now > self.expires_at + skew

    def not_yet_valid(self, now: datetime, skew: timedelta = DEFAULT_SKEW) -> bool:
        """Whether the token's not-before still lies in the future (with
        skew slack)."""
        return self.not_before is not None and now + skew < self.not_before


@dataclass
class OperatorClaims(Claims):
    """Verified content of a self-signed operator token."""

    # epoch is the trust domain's current epoch.
    epoch: int = 0
    # ext carries the named extension claims, decoded from JSON.
    ext: dict[str, Any] = field(default_factory=dict)


@dataclass
class AccountClaims(Claims):
    """Verified content of an account (tenant) token."""

    # name is the tenant's human-readable label; falls back to the subject
    # key when the token carries no name.
    name: str = ""
    # epoch is the trust-domain epoch the token was issued in.
    epoch: int = 0
    # ext carries the named extension claims, decoded from JSON.
    ext: dict[str, Any] = field(default_factory=dict)


@dataclass
class UserClaims(Claims):
    """Verified content of a user token."""

    # name is the user's human-readable label; falls back to the subject
    # key when the token carries no name.
    name: str = ""
    # epoch is the trust-domain epoch the token was issued in.
    epoch: int = 0
    # bearer marks a token whose holder authenticates by the token alone,
    # without per-request signatures.
    bearer: bool = False
    # ext carries the named extension claims, decoded from JSON.
    ext: dict[str, Any] = field(default_factory=dict)


def _extensions_claim(extensions: Iterable[Extension]) -> dict[str, Any]:
    ext: dict[str, Any] = {}
    for e in extensions:
        name = e.extension_name()
        if not name:
            raise ValissError("valiss: extension name must not be empty")
        if name in ext:
            raise ValissError(f'valiss: duplicate extension "{name}"')
        ext[name] = e.extension_payload()
    # Go marshals map keys sorted; match it so identical claims serialize
    # identically on both sides.
    return dict(sorted(ext.items()))


def _validity(
    ttl: timedelta | None, expiry: datetime | None, not_before: datetime | None, now: datetime
) -> tuple[int, int]:
    if ttl is not None and expiry is not None:
        raise ValissError("valiss: ttl and expiry are mutually exclusive")
    expires = 0
    if ttl is not None:
        if ttl <= timedelta(0):
            raise ValissError("valiss: ttl must be positive")
        expires = int((now + ttl).timestamp())
    elif expiry is not None:
        expires = int(expiry.timestamp())
    nbf = int(not_before.timestamp()) if not_before is not None else 0
    return expires, nbf


def _encode_token(
    issuer: nkeys.KeyPair,
    name: str,
    subject: str,
    body: dict[str, Any],
    expires: int,
    not_before: int,
    now: datetime,
) -> str:
    """Encode and sign the JWT. Field order matches the Go wire struct
    (jti, iat, iss, name, sub, exp, nbf, valiss), keeping the jti hash
    algorithm identical: base32 SHA-256 of the claims with jti absent."""
    claims: dict[str, Any] = {"iat": int(now.timestamp()), "iss": issuer.public_key}
    if name:
        claims["name"] = name
    claims["sub"] = subject
    if expires:
        claims["exp"] = expires
    if not_before:
        claims["nbf"] = not_before
    claims["valiss"] = body
    unhashed = json.dumps(claims, separators=(",", ":"), ensure_ascii=False).encode()
    jti = base64.b32encode(hashlib.sha256(unhashed).digest()).decode("ascii").rstrip("=")
    payload = {"jti": jti, **claims}
    signing_input = (
        _b64url(_TOKEN_HEADER.encode())
        + "."
        + _b64url(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode())
    )
    signature = _b64url(issuer.sign(signing_input.encode()))
    return f"{signing_input}.{signature}"


def issue_operator(
    operator: nkeys.KeyPair,
    *,
    ttl: timedelta | None = None,
    expiry: datetime | None = None,
    not_before: datetime | None = None,
    epoch: int = 0,
    extensions: Iterable[Extension] = (),
    now: datetime | None = None,
) -> str:
    """Mint the self-signed operator token: the trust domain's policy
    statement (epoch, validity window, extensions), signed by the operator
    key over its own public key."""
    if not nkeys.is_valid_public_operator_key(operator.public_key):
        raise ValissError(
            "valiss: operator tokens must be signed by an operator-type nkey (expected an SO... seed)"
        )
    now = now or _now()
    expires, nbf = _validity(ttl, expiry, not_before, now)
    body: dict[str, Any] = {"type": _OPERATOR_TYPE}
    if epoch:
        body["epoch"] = epoch
    if ext := _extensions_claim(extensions):
        body["ext"] = ext
    return _encode_token(operator, "", operator.public_key, body, expires, nbf, now)


def issue_account(
    operator: nkeys.KeyPair,
    name: str,
    account_pub_key: str,
    *,
    ttl: timedelta | None = None,
    expiry: datetime | None = None,
    not_before: datetime | None = None,
    epoch: int = 0,
    extensions: Iterable[Extension] = (),
    now: datetime | None = None,
) -> str:
    """Mint an account token signed by the operator key. The token subject
    is the tenant's account public key and name carries the tenant id; the
    tenant signs requests with the seed matching the subject key."""
    if not nkeys.is_valid_public_operator_key(operator.public_key):
        raise ValissError(
            "valiss: account tokens must be signed by an operator-type nkey (expected an SO... seed)"
        )
    if not nkeys.is_valid_public_account_key(account_pub_key):
        raise ValissError("valiss: invalid tenant public key (expected an A... nkey)")
    now = now or _now()
    expires, nbf = _validity(ttl, expiry, not_before, now)
    body: dict[str, Any] = {"type": _ACCOUNT_TYPE}
    if epoch:
        body["epoch"] = epoch
    if ext := _extensions_claim(extensions):
        body["ext"] = ext
    return _encode_token(operator, name, account_pub_key, body, expires, nbf, now)


def issue_user(
    account: nkeys.KeyPair,
    name: str,
    user_pub_key: str,
    *,
    ttl: timedelta | None = None,
    expiry: datetime | None = None,
    not_before: datetime | None = None,
    epoch: int = 0,
    bearer: bool = False,
    extensions: Iterable[Extension] = (),
    now: datetime | None = None,
) -> str:
    """Mint a user token signed by a tenant's account key, delegating to an
    end user. The token subject is the user's public key and name carries
    the user id.

    ``bearer=True`` produces a token the server accepts without per-request
    signatures. Bearer tokens are replayable until they expire or their
    account leaves the allowlist, so pair them with TLS and a short ttl.
    """
    if not nkeys.is_valid_public_account_key(account.public_key):
        raise ValissError(
            "valiss: user tokens must be signed by an account-type nkey (expected an SA... seed)"
        )
    if not nkeys.is_valid_public_user_key(user_pub_key):
        raise ValissError("valiss: invalid user public key (expected a U... nkey)")
    now = now or _now()
    expires, nbf = _validity(ttl, expiry, not_before, now)
    body: dict[str, Any] = {"type": _USER_TYPE}
    if epoch:
        body["epoch"] = epoch
    if bearer:
        body["bearer"] = True
    if ext := _extensions_claim(extensions):
        body["ext"] = ext
    return _encode_token(account, name, user_pub_key, body, expires, nbf, now)


def _decode_payload(token: str) -> dict[str, Any]:
    """Parse a token and verify its signature against the issuer key
    embedded in the claims. Trust is NOT established here: the caller must
    check the issuer's place in the chain."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValissError("valiss: malformed token")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValissError(f"valiss: bad token: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValissError("valiss: bad token structure")
    if header.get("typ") != "JWT" or header.get("alg") != "ed25519-nkey":
        raise ValissError(
            f"valiss: unsupported token type {header.get('typ')}/{header.get('alg')}"
        )
    issuer = payload.get("iss", "")
    signature = _b64url_decode(parts[2])
    try:
        nkeys.from_public_key(issuer).verify(f"{parts[0]}.{parts[1]}".encode(), signature)
    except ValissError as exc:
        raise ValissError("valiss: token signature verification failed") from exc
    return payload


def _ts(value: Any) -> datetime | None:
    if not value:
        return None
    return datetime.fromtimestamp(int(value), tz=timezone.utc)


def _claims_of(payload: dict[str, Any]) -> Claims:
    return Claims(
        id=payload.get("jti", ""),
        issuer=payload.get("iss", ""),
        subject=payload.get("sub", ""),
        issued_at=_ts(payload.get("iat")),
        expires_at=_ts(payload.get("exp")),
        not_before=_ts(payload.get("nbf")),
    )


def _body_of(payload: dict[str, Any], expected_type: str) -> dict[str, Any]:
    body = payload.get("valiss")
    if not isinstance(body, dict):
        raise ValissError("valiss: token carries no valiss claims")
    if body.get("type") != expected_type:
        article = "an" if expected_type[0] in "ao" else "a"
        raise ValissError(
            f"valiss: not {article} {expected_type} token (type {body.get('type')!r})"
        )
    return body


def _ext_of(body: dict[str, Any]) -> dict[str, Any]:
    ext = body.get("ext")
    return ext if isinstance(ext, dict) else {}


def verify_operator(token: str, operator_pub_key: str) -> OperatorClaims:
    """Decode a self-signed operator token, check its type and that it is
    signed by the pinned operator key over itself, and return the claims.
    Expiry and activation checks are the caller's."""
    payload = _decode_payload(token)
    body = _body_of(payload, _OPERATOR_TYPE)
    c = _claims_of(payload)
    if c.issuer != operator_pub_key or c.subject != operator_pub_key:
        raise ValissError("valiss: operator token not self-signed by the expected operator")
    if not nkeys.is_valid_public_operator_key(c.subject):
        raise ValissError("valiss: operator token subject is not an operator public key")
    return OperatorClaims(
        **vars(c), epoch=int(body.get("epoch") or 0), ext=_ext_of(body)
    )


def verify_account(token: str, operator_pub_key: str) -> AccountClaims:
    """Decode an account token, check its type, signature, and issuer, and
    return the claims. It does NOT check expiry, activation, or the
    allowlist; server-side verification stays with the Go implementation."""
    payload = _decode_payload(token)
    body = _body_of(payload, _ACCOUNT_TYPE)
    c = _claims_of(payload)
    if c.issuer != operator_pub_key:
        raise ValissError("valiss: account token not signed by the expected issuer")
    if not nkeys.is_valid_public_account_key(c.subject):
        raise ValissError("valiss: account token subject is not an account public key")
    return AccountClaims(
        **vars(c),
        name=payload.get("name") or c.subject,
        epoch=int(body.get("epoch") or 0),
        ext=_ext_of(body),
    )


def verify_user(token: str, account_pub_key: str) -> UserClaims:
    """Decode a user token, check its type, signature, and issuer (the
    account public key that delegated it), and return the claims. Expiry
    and activation checks are the caller's."""
    payload = _decode_payload(token)
    body = _body_of(payload, _USER_TYPE)
    c = _claims_of(payload)
    if c.issuer != account_pub_key:
        raise ValissError("valiss: user token not signed by the expected account")
    if not nkeys.is_valid_public_user_key(c.subject):
        raise ValissError("valiss: user token subject is not a user public key")
    return UserClaims(
        **vars(c),
        name=payload.get("name") or c.subject,
        epoch=int(body.get("epoch") or 0),
        bearer=bool(body.get("bearer")),
        ext=_ext_of(body),
    )


def decode(token: str) -> Claims:
    """Parse a token of any level without establishing trust: the signature
    is checked against the token's own embedded issuer only. For inspection
    and tooling."""
    return _claims_of(_decode_payload(token))


def issuer_of(token: str) -> str:
    """Public key that signed a token, after checking the token's own
    signature against it. Does not establish trust: the caller must still
    verify the issuer's place in the chain."""
    return _decode_payload(token).get("iss", "")


def new_nonce() -> str:
    """Fresh random per-request nonce (128 bits, hex). Client transports use
    it when the server has a replay cache; the transport folds it into the
    signed request context."""
    return os.urandom(16).hex()


def _signed_payload(timestamp: str, context: bytes) -> bytes:
    """Canonical byte string a subject signs per request: the timestamp
    bound to a hash of the request context. Binding the context (the
    transport's canonical method/path) stops a captured signature from
    authorizing a different operation; the timestamp and skew window bound
    replay of the same operation."""
    return f"{timestamp}\n{hashlib.sha256(context).hexdigest()}".encode()


def sign_request(
    subject: nkeys.KeyPair, context: bytes = b"", now: datetime | None = None
) -> tuple[str, str]:
    """Produce the timestamp and base64 signature a subject attaches to a
    request, signing the timestamp bound to the request context with its
    nkey seed.

    context is the transport's canonical description of the request (e.g.
    method and path); the server must reconstruct identical bytes. An empty
    context binds nothing beyond the timestamp.
    """
    timestamp = _rfc3339nano(now or _now())
    signature = base64.b64encode(subject.sign(_signed_payload(timestamp, context))).decode("ascii")
    return timestamp, signature


def verify_signature(
    subject_pub_key: str,
    timestamp: str,
    signature: str,
    context: bytes = b"",
    now: datetime | None = None,
    skew: timedelta = DEFAULT_SKEW,
) -> None:
    """Check a request signature against the subject public key, bound the
    timestamp to a symmetric skew window around now, and confirm it was
    signed over the request context (see sign_request)."""
    now = now or _now()
    try:
        ts = datetime.fromisoformat(timestamp)
    except ValueError as exc:
        raise ValissError(f"valiss: bad request timestamp: {exc}") from exc
    if ts.tzinfo is None:
        raise ValissError("valiss: bad request timestamp: missing timezone offset")
    drift = now - ts
    if drift > skew or drift < -skew:
        raise ValissError(f"valiss: request timestamp outside the {skew} skew window")
    try:
        raw_sig = base64.b64decode(signature, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValissError(f"valiss: bad request signature encoding: {exc}") from exc
    try:
        pub = nkeys.from_public_key(subject_pub_key)
    except ValissError as exc:
        raise ValissError(f"valiss: bad subject public key: {exc}") from exc
    # The payload embeds the raw timestamp string as received: canonical
    # RFC3339Nano round-trips exactly, and Python cannot re-render Go's
    # nanosecond precision.
    try:
        pub.verify(_signed_payload(timestamp, context), raw_sig)
    except ValissError as exc:
        raise ValissError("valiss: request signature verification failed") from exc
