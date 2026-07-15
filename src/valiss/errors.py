"""Error type shared by every valiss module, plus the spec §7 reason codes.

Every failure raises :class:`ValissError`; its ``reason`` attribute, when set,
is the stable spec §7 reason code the failure reduces to. The human-readable
message is illustrative and prefixed ``valiss:`` to match the Go
implementation; conformance and cross-implementation comparisons key off
``reason``, never the message text.
"""

from __future__ import annotations


class Reason:
    """Stable spec §7 reason codes.

    A conformant verifier distinguishes these failure conditions so negative
    conformance vectors can assert the same reason across implementations. The
    codes mirror SPEC-1.md §7 verbatim; an implementation may subdivide
    internally but every failure reduces to one of these.
    """

    # §7.1 envelope / decode
    MALFORMED = "malformed"
    UNSUPPORTED_TYPE = "unsupported_type"
    UNSUPPORTED_VERSION = "unsupported_version"
    BAD_ISSUER_KEY = "bad_issuer_key"
    BAD_SIGNATURE = "bad_signature"

    # §7.2 token semantics
    WRONG_TYPE = "wrong_type"
    WRONG_ISSUER = "wrong_issuer"
    WRONG_SUBJECT_ROLE = "wrong_subject_role"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    EPOCH_MISMATCH = "epoch_mismatch"

    # §7.3 request / credential
    MISSING = "missing"
    NO_RESOLVER = "no_resolver"
    UNKNOWN_OPERATOR = "unknown_operator"
    NOT_ALLOWLISTED = "not_allowlisted"
    NOT_BEARER = "not_bearer"
    SKEW = "skew"
    BAD_SIGNATURE_ENCODING = "bad_signature_encoding"
    BAD_REQUEST_SIGNATURE = "bad_request_signature"
    NONCE_REQUIRED = "nonce_required"
    REPLAY = "replay"
    OPERATOR_MISCONFIGURED = "operator_misconfigured"
    EXTENSION_INVALID = "extension_invalid"
    VALIDATOR_REJECTED = "validator_rejected"

    # §7.4 message-specific
    NO_CHAIN = "no_chain"
    CHAIN_MISMATCH = "chain_mismatch"
    CHAIN_USER_MISMATCH = "chain_user_mismatch"
    WRONG_AUDIENCE = "wrong_audience"
    CHECKSUM_MISSING = "checksum_missing"
    CHECKSUM_MISMATCH = "checksum_mismatch"


class ValissError(Exception):
    """Any authentication, encoding, or credential failure.

    Messages are prefixed ``valiss:`` to match the Go implementation. The
    optional ``reason`` is the spec §7 reason code (see :class:`Reason`) the
    failure reduces to, for conformance testing and programmatic handling;
    it is ``None`` for failures outside the verification taxonomy (for
    example minting a token with the wrong key level).
    """

    def __init__(self, message: str, *, reason: str | None = None):
        super().__init__(message)
        self.reason = reason
