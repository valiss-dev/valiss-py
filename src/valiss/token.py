"""Core of the valiss tenant authentication scheme.

Wire-compatible Python port of valiss.dev/valiss, scoped to the client side:
minting tokens and signing requests. Chain verification with allowlists,
epoch policy, and extension enforcement stays with the Go server; the
``verify_*`` functions here check a single token's signature, type, and
issuer for tooling and tests.

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

Tokens are nkey-signed JWTs (``ed25519-nkey`` algorithm) carrying an explicit
wire-format version in the header. A verifier reads the version before
parsing the payload and dispatches to the matching per-version decoder, so a
future spec version can coexist with this one; an unrecognized version is
rejected cleanly rather than mis-parsed. The ``valiss`` payload section
carries the scheme's typed claim bodies. Authorization rides named extension
claims (``extensions=``): typed payloads the scheme signs and transports but
assigns no meaning. The httpauth and grpcauth modules provide the transport
extensions Go servers enforce.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol, Self, TypeVar

from . import nkeys
from .errors import Reason, ValissError

# Header field names carrying the credential on each request. Used as gRPC
# metadata keys and HTTP header names alike.
HEADER_ACCOUNT_TOKEN = "valiss-account-token"
HEADER_USER_TOKEN = "valiss-user-token"
HEADER_TIMESTAMP = "valiss-timestamp"
HEADER_SIGNATURE = "valiss-signature"
HEADER_NONCE = "valiss-nonce"

# Bounds request-timestamp drift and token-expiry slack.
DEFAULT_SKEW = timedelta(minutes=2)

# The current wire-format version. It appears on the wire only as an integer:
# the ``ver`` header field on tokens, the ``VALISS-CREDS-VERSION`` line on
# creds files, and the ``valiss-req-v1`` prefix on request signatures. Adding a
# version is additive — a new per-version decoder plus one dispatch case — so
# the version never leaks into the public function or type names.
_WIRE_VERSION = 1

# Frozen, byte-exact version-1 token header. Producers emit it verbatim; it
# must stay in sync with _WIRE_VERSION.
_TOKEN_HEADER_V1 = '{"typ":"JWT","alg":"ed25519-nkey","ver":1}'

# Version tag bound into the version-1 request-signature bytes (section 5.1).
# Because it is part of the signed bytes, a v1 reconstruction fails closed on a
# signature made under any other version rather than mis-verifying it.
_REQUEST_PREFIX_V1 = "valiss-req-v1\n"

# RFC 3339 (with optional nanosecond fraction), matching Go time.RFC3339Nano:
# a 'T' separator and a 'Z' or colon-separated numeric offset, no space
# separator and no lowercase 't'.
_RFC3339NANO = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})")

_OPERATOR_TYPE = "operator"
_ACCOUNT_TYPE = "account"
_USER_TYPE = "user"
_MESSAGE_TYPE = "message"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


# The base64url alphabet (no padding). Go's base64.RawURLEncoding accepts only
# these characters; in particular it rejects the standard-alphabet "+" and "/",
# which Python's b64decode would otherwise fold onto "-"/"_".
_B64URL_ALPHABET = re.compile(r"[A-Za-z0-9_-]*")


def _b64url_decode(encoded: str) -> bytes:
    """Strict base64url (no padding) decode, matching Go's
    base64.RawURLEncoding: a character outside the base64url alphabet (including
    the standard "+"/"/") or a bad length is a malformed artifact."""
    if _B64URL_ALPHABET.fullmatch(encoded) is None:
        raise ValissError("valiss: malformed token", reason=Reason.MALFORMED)
    pad = "=" * (-len(encoded) % 4)
    try:
        return base64.urlsafe_b64decode(encoded + pad)
    except (binascii.Error, ValueError) as exc:
        raise ValissError("valiss: malformed token", reason=Reason.MALFORMED) from exc


def _go_json(obj: Any) -> bytes:
    """Serialize like Go's ``encoding/json``: no insignificant whitespace and
    HTML-escaping of ``<``, ``>``, ``&`` (plus U+2028/U+2029). Reproducing this
    byte-for-byte is what keeps the content-derived ``jti`` identical across
    implementations (section 3.2). Those characters are only ever escaped
    inside JSON string values, so post-serialization replacement is safe."""
    s = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    s = s.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    s = s.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return s.encode("utf-8")


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


class DecodableExtension(Protocol):
    """A verification-side extension: it names itself (the zero value reports
    the name, as for the mint-side :class:`Extension`) and decodes a JSON
    payload into a typed instance. Transport extensions (``httpauth.Ext``,
    ``grpcauth.Ext``) and consumer extensions implement it so a verifier can
    enforce them and a handler can read them back with :func:`ext_of`."""

    def extension_name(self) -> str: ...

    @classmethod
    def decode(cls, payload: Mapping[str, Any], /) -> Self: ...


_Ext = TypeVar("_Ext", bound=DecodableExtension)


def covered(granted: Iterable[str], required: str) -> bool:
    """Whether any granted pattern covers ``required``, honoring a trailing
    ``*`` prefix wildcard (so ``"/v1/*"`` covers ``"/v1/x"`` and ``"*"`` covers
    everything). The transport extensions use it for paths and methods; mirrors
    Go ``Covered``/``scopeMatch``."""
    for pattern in granted:
        if pattern.endswith("*"):
            if required.startswith(pattern[:-1]):
                return True
        elif pattern == required:
            return True
    return False


def ext_of(ext: Mapping[str, Any], ext_type: type[_Ext]) -> _Ext | None:
    """Decode the extension named by ``ext_type``'s zero value out of an ``ext``
    map, or ``None`` when absent. Raises :class:`ValissError` with
    ``reason=extension_invalid`` on a malformed payload. The typed Python analog
    of Go ``ExtOf[T]``; ``ext_type`` must be zero-constructible (as the
    dataclass extensions are)."""
    name = ext_type().extension_name()
    payload = ext.get(name)
    if payload is None:
        return None
    if not isinstance(payload, Mapping):
        raise ValissError(
            f"valiss: extension {name!r} is not an object", reason=Reason.EXTENSION_INVALID
        )
    try:
        return ext_type.decode(payload)
    except (ValueError, TypeError, KeyError) as exc:
        raise ValissError(
            f"valiss: decode extension {name!r}: {exc}", reason=Reason.EXTENSION_INVALID
        ) from exc


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
        """Whether the token has passed its expiry (with skew slack). Written as
        ``now - skew > exp`` (equivalent to ``now > exp + skew``) so the skew is
        added to the bounded verification instant, never to an ``exp`` that may
        sit near datetime's maximum."""
        return self.expires_at is not None and now - skew > self.expires_at

    def not_yet_valid(self, now: datetime, skew: timedelta = DEFAULT_SKEW) -> bool:
        """Whether the token's not-before still lies in the future (with
        skew slack)."""
        return self.not_before is not None and now + skew < self.not_before


@dataclass
class OperatorClaims(Claims):
    """Verified content of a self-signed operator token."""

    # name is the trust domain's human-readable label; falls back to the
    # subject key when the token carries no name.
    name: str = ""
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


def _encode_v1(
    issuer: nkeys.KeyPair,
    body: dict[str, Any],
    *,
    name: str = "",
    subject: str = "",
    audience: str = "",
    expires: int = 0,
    not_before: int = 0,
    now: datetime,
) -> str:
    """Encode and sign a version-1 token. Field order matches the Go wire
    struct (jti, iat, iss, name, sub, aud, exp, nbf, valiss) with empty
    fields omitted, keeping the jti derivation identical: unpadded base32
    SHA-256 of the claims JSON with jti absent (section 3.5)."""
    claims: dict[str, Any] = {"iat": int(now.timestamp()), "iss": issuer.public_key}
    if name:
        claims["name"] = name
    if subject:
        claims["sub"] = subject
    if audience:
        claims["aud"] = audience
    if expires:
        claims["exp"] = expires
    if not_before:
        claims["nbf"] = not_before
    claims["valiss"] = body
    jti = base64.b32encode(hashlib.sha256(_go_json(claims)).digest()).decode("ascii").rstrip("=")
    payload = {"jti": jti, **claims}
    signing_input = _b64url(_TOKEN_HEADER_V1.encode()) + "." + _b64url(_go_json(payload))
    signature = _b64url(issuer.sign(signing_input.encode()))
    return f"{signing_input}.{signature}"


def issue_operator(
    operator: nkeys.KeyPair,
    *,
    name: str = "",
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
    return _encode_v1(
        operator, body, name=name, subject=operator.public_key,
        expires=expires, not_before=nbf, now=now,
    )


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
    return _encode_v1(
        operator, body, name=name, subject=account_pub_key,
        expires=expires, not_before=nbf, now=now,
    )


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
    return _encode_v1(
        account, body, name=name, subject=user_pub_key,
        expires=expires, not_before=nbf, now=now,
    )


@dataclass
class _Decoded:
    """Version-neutral view of a parsed, signature-verified token. Per-version
    decoders normalize their wire layout into it, so the public verify paths
    never depend on a wire version. Body fields are the union across levels; a
    level leaves the ones it does not use at their zero value."""

    id: str
    issuer: str
    subject: str
    name: str
    audience: str
    issued_at: int
    expires: int
    not_before: int
    type: str
    epoch: int
    bearer: bool
    checksum: str
    chain: dict[str, Any] | None
    ext: dict[str, Any]


def _peek_version(token: str) -> tuple[int, list[str]]:
    """Read the wire-format version from a token's header without decoding its
    payload, returning the version and the three JWS segments. Version-agnostic:
    it checks only the envelope shape (three parts, JSON header, JWT /
    ed25519-nkey) common to all versions, so it never changes as versions are
    added."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValissError("valiss: malformed token", reason=Reason.MALFORMED)
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValissError(f"valiss: token header: {exc}", reason=Reason.MALFORMED) from exc
    if not isinstance(header, dict):
        raise ValissError("valiss: token header: not an object", reason=Reason.MALFORMED)
    if header.get("typ") != "JWT" or header.get("alg") != "ed25519-nkey":
        raise ValissError(
            f"valiss: unsupported token type {header.get('typ')}/{header.get('alg')}",
            reason=Reason.UNSUPPORTED_TYPE,
        )
    ver = header.get("ver", 0)
    # ver must be a JSON integer in Go's int range; a bool, a float, or an
    # out-of-range number fails Go's header unmarshal (malformed) rather than
    # dispatching to an unsupported version.
    if isinstance(ver, bool) or not isinstance(ver, int) or ver < _INT64_MIN or ver > _INT64_MAX:
        raise ValissError("valiss: malformed token header version", reason=Reason.MALFORMED)
    return ver, parts


def _decode_token(token: str) -> _Decoded:
    """Parse a token, verify its signature against the issuer key embedded in
    the claims, and return a version-neutral view. Dispatches on the wire
    version read from the header; an unrecognized version is rejected without
    parsing the payload. Trust is NOT established here: the caller must check
    the issuer's place in the chain."""
    ver, parts = _peek_version(token)
    if ver == _WIRE_VERSION:
        return _decode_v1(parts)
    raise ValissError(f"valiss: unsupported wire version {ver}", reason=Reason.UNSUPPORTED_VERSION)


def _decode_v1(parts: list[str]) -> _Decoded:
    """Parse a version-1 payload, verify the signature, and normalize into
    _Decoded. Field types are validated up front (a wrong type is malformed),
    then the issuer key is decoded and the signature verified — the same order
    as Go's typed json.Unmarshal, so a type/shape error is reported as
    malformed before signature verification rather than mis-parsed."""
    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValissError(f"valiss: token claims: {exc}", reason=Reason.MALFORMED) from exc
    if not isinstance(payload, dict):
        raise ValissError("valiss: token claims: not an object", reason=Reason.MALFORMED)
    d = _decoded_of(payload)
    try:
        kp = nkeys.from_public_key(d.issuer)
    except ValissError as exc:
        raise ValissError(f"valiss: token issuer: {exc}", reason=Reason.BAD_ISSUER_KEY) from exc
    sig = _b64url_decode(parts[2])
    try:
        kp.verify(f"{parts[0]}.{parts[1]}".encode(), sig)
    except ValissError as exc:
        raise ValissError(
            "valiss: token signature verification failed", reason=Reason.BAD_SIGNATURE
        ) from exc
    return d


# Go decodes iat/exp/nbf as int64 and epoch as uint64; a value outside the type
# range (or a non-integer JSON number) fails the unmarshal. Timestamps are
# additionally bounded to what datetime can represent (roughly years 1..9999),
# so a value Go would accept but Python cannot render is rejected cleanly
# instead of raising OverflowError.
_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1
_UINT64_MAX = 2**64 - 1
_TS_MIN = -62135596800  # 0001-01-01T00:00:00Z
_TS_MAX = 253402300799  # 9999-12-31T23:59:59Z


def _wire_str(obj: dict[str, Any], key: str) -> str:
    """A JSON string field, or "" when absent/null; any other JSON type is a
    malformed token (Go unmarshals these into string fields)."""
    v = obj.get(key)
    if v is None:
        return ""
    if not isinstance(v, str):
        raise ValissError(f"valiss: token claims: {key} is not a string", reason=Reason.MALFORMED)
    return v


def _wire_int(obj: dict[str, Any], key: str, lo: int, hi: int) -> int:
    """A JSON integer field in [lo, hi], or 0 when absent/null; a non-integer
    (including a bool or a float) or out-of-range value is malformed."""
    v = obj.get(key)
    if v is None:
        return 0
    if isinstance(v, bool) or not isinstance(v, int) or v < lo or v > hi:
        raise ValissError(f"valiss: token claims: {key} is not a valid integer", reason=Reason.MALFORMED)
    return v


def _wire_bool(obj: dict[str, Any], key: str) -> bool:
    """A JSON boolean field, or False when absent/null; any other type is
    malformed (Go unmarshals bearer into a bool)."""
    v = obj.get(key)
    if v is None:
        return False
    if not isinstance(v, bool):
        raise ValissError(f"valiss: token claims: {key} is not a boolean", reason=Reason.MALFORMED)
    return v


def _wire_obj(obj: dict[str, Any], key: str) -> dict[str, Any] | None:
    """A JSON object field, or None when absent/null; any other type is
    malformed (Go unmarshals chain/ext into a struct/map)."""
    v = obj.get(key)
    if v is None:
        return None
    if not isinstance(v, dict):
        raise ValissError(f"valiss: token claims: {key} is not an object", reason=Reason.MALFORMED)
    return v


def _decoded_of(payload: dict[str, Any]) -> _Decoded:
    body = _wire_obj(payload, "valiss") or {}
    return _Decoded(
        id=_wire_str(payload, "jti"),
        issuer=_wire_str(payload, "iss"),
        subject=_wire_str(payload, "sub"),
        name=_wire_str(payload, "name"),
        audience=_wire_str(payload, "aud"),
        issued_at=_wire_int(payload, "iat", _TS_MIN, _TS_MAX),
        expires=_wire_int(payload, "exp", _TS_MIN, _TS_MAX),
        not_before=_wire_int(payload, "nbf", _TS_MIN, _TS_MAX),
        type=_wire_str(body, "type"),
        epoch=_wire_int(body, "epoch", 0, _UINT64_MAX),
        bearer=_wire_bool(body, "bearer"),
        checksum=_wire_str(body, "checksum"),
        chain=_wire_obj(body, "chain"),
        ext=_wire_obj(body, "ext") or {},
    )


def _ts(value: int) -> datetime | None:
    if not value:
        return None
    return datetime.fromtimestamp(value, tz=timezone.utc)


def _claims_of(d: _Decoded) -> Claims:
    return Claims(
        id=d.id,
        issuer=d.issuer,
        subject=d.subject,
        issued_at=_ts(d.issued_at),
        expires_at=_ts(d.expires),
        not_before=_ts(d.not_before),
    )


def _name_of(name: str, subject: str) -> str:
    """Fall back to the subject key when a token carries no name."""
    return name if name else subject


def verify_operator(token: str, operator_pub_key: str) -> OperatorClaims:
    """Decode a self-signed operator token, check its type and that it is
    signed by the pinned operator key over itself, and return the claims.
    Expiry and activation checks are the caller's."""
    d = _decode_token(token)
    if d.type != _OPERATOR_TYPE:
        raise ValissError(f"valiss: not an operator token (type {d.type!r})", reason=Reason.WRONG_TYPE)
    if d.issuer != operator_pub_key or d.subject != operator_pub_key:
        raise ValissError(
            "valiss: operator token not self-signed by the expected operator",
            reason=Reason.WRONG_ISSUER,
        )
    if not nkeys.is_valid_public_operator_key(d.subject):
        raise ValissError(
            "valiss: operator token subject is not an operator public key",
            reason=Reason.WRONG_SUBJECT_ROLE,
        )
    return OperatorClaims(
        **vars(_claims_of(d)), name=_name_of(d.name, d.subject), epoch=d.epoch, ext=d.ext
    )


def verify_account(token: str, operator_pub_key: str) -> AccountClaims:
    """Decode an account token, check its type, signature, and issuer, and
    return the claims. It does NOT check expiry, activation, or the
    allowlist; server-side verification stays with the Go implementation."""
    d = _decode_token(token)
    if d.type != _ACCOUNT_TYPE:
        raise ValissError(f"valiss: not an account token (type {d.type!r})", reason=Reason.WRONG_TYPE)
    if d.issuer != operator_pub_key:
        raise ValissError(
            "valiss: account token not signed by the expected issuer", reason=Reason.WRONG_ISSUER
        )
    if not nkeys.is_valid_public_account_key(d.subject):
        raise ValissError(
            "valiss: account token subject is not an account public key",
            reason=Reason.WRONG_SUBJECT_ROLE,
        )
    return AccountClaims(
        **vars(_claims_of(d)), name=_name_of(d.name, d.subject), epoch=d.epoch, ext=d.ext
    )


def verify_user(token: str, account_pub_key: str) -> UserClaims:
    """Decode a user token, check its type, signature, and issuer (the
    account public key that delegated it), and return the claims. Expiry
    and activation checks are the caller's."""
    d = _decode_token(token)
    if d.type != _USER_TYPE:
        raise ValissError(f"valiss: not a user token (type {d.type!r})", reason=Reason.WRONG_TYPE)
    if d.issuer != account_pub_key:
        raise ValissError(
            "valiss: user token not signed by the expected account", reason=Reason.WRONG_ISSUER
        )
    if not nkeys.is_valid_public_user_key(d.subject):
        raise ValissError(
            "valiss: user token subject is not a user public key", reason=Reason.WRONG_SUBJECT_ROLE
        )
    return UserClaims(
        **vars(_claims_of(d)),
        name=_name_of(d.name, d.subject),
        epoch=d.epoch,
        bearer=d.bearer,
        ext=d.ext,
    )


def decode(token: str) -> Claims:
    """Parse a token of any level without establishing trust: the signature
    is checked against the token's own embedded issuer only. For inspection
    and tooling."""
    return _claims_of(_decode_token(token))


def issuer_of(token: str) -> str:
    """Public key that signed a token, after checking the token's own
    signature against it. Does not establish trust: the caller must still
    verify the issuer's place in the chain."""
    return _decode_token(token).issuer


def new_nonce() -> str:
    """Fresh random per-request nonce (128 bits, hex). Client transports use
    it when the server has a replay cache; the transport folds it into the
    signed request context."""
    return os.urandom(16).hex()


def _signed_payload(timestamp: str, context: bytes) -> bytes:
    """Canonical byte string a subject signs per request (section 5.1): a
    version tag, then the timestamp bound to a hash of the request context.
    The version tag is part of the signed bytes, so a signature made under any
    other version cannot match a v1 reconstruction; binding the context (the
    transport's canonical method/path) stops a captured signature from
    authorizing a different operation, and the timestamp and skew window bound
    replay of the same operation."""
    return f"{_REQUEST_PREFIX_V1}{timestamp}\n{hashlib.sha256(context).hexdigest()}".encode()


def sign_request(
    subject: nkeys.KeyPair, context: bytes = b"", now: datetime | None = None
) -> tuple[str, str]:
    """Produce the timestamp and base64 signature a subject attaches to a
    request, signing the timestamp bound to the request context with its
    nkey seed.

    context is the transport's canonical description of the request (e.g.
    method and path); the server must reconstruct identical bytes. An empty
    context binds nothing beyond the version tag and timestamp.
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
    # Go parses the timestamp with time.RFC3339Nano, which is stricter than
    # datetime.fromisoformat: it requires the 'T' separator, a 'Z' or a
    # colon-separated numeric offset, and rejects a space separator or a
    # lowercase 't'. Gate on that shape so a non-RFC3339 timestamp maps to skew
    # (as Go does) rather than sneaking through to the signature check.
    if _RFC3339NANO.fullmatch(timestamp) is None:
        raise ValissError("valiss: bad request timestamp", reason=Reason.SKEW)
    try:
        ts = datetime.fromisoformat(timestamp)
    except ValueError as exc:
        raise ValissError(f"valiss: bad request timestamp: {exc}", reason=Reason.SKEW) from exc
    drift = now - ts
    if drift > skew or drift < -skew:
        raise ValissError(
            f"valiss: request timestamp outside the {skew} skew window", reason=Reason.SKEW
        )
    try:
        raw_sig = base64.b64decode(signature, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValissError(
            f"valiss: bad request signature encoding: {exc}", reason=Reason.BAD_SIGNATURE_ENCODING
        ) from exc
    try:
        pub = nkeys.from_public_key(subject_pub_key)
    except ValissError as exc:
        raise ValissError(
            f"valiss: bad subject public key: {exc}", reason=Reason.BAD_REQUEST_SIGNATURE
        ) from exc
    # The payload embeds the raw timestamp string as received: canonical
    # RFC3339Nano round-trips exactly, and Python cannot re-render Go's
    # nanosecond precision.
    try:
        pub.verify(_signed_payload(timestamp, context), raw_sig)
    except ValissError as exc:
        raise ValissError(
            "valiss: request signature verification failed", reason=Reason.BAD_REQUEST_SIGNATURE
        ) from exc
