"""Robustness / Go-parity hardening: malformed or adversarial artifacts must
be rejected cleanly with the right spec §7 reason — never crash, never
silently accepted where Go rejects. These lock in the fixes surfaced by the
cross-implementation review; none are exercised by the frozen vectors (which
carry only well-typed inputs), so they guard against regressions.
"""

import base64
import json
from datetime import datetime, timezone

import pytest

from valiss import creds, nkeys, token
from valiss.errors import ValissError

NOW = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _token(payload: dict, header: dict | None = None, sig: str = "AAAA") -> str:
    """A JWS string with an arbitrary (unsigned) payload. Type/shape checks run
    before signature verification, so a dummy signature is fine for asserting a
    decode-stage rejection."""
    hdr = header if header is not None else {"typ": "JWT", "alg": "ed25519-nkey", "ver": 1}
    h = _b64u(json.dumps(hdr, separators=(",", ":")).encode())
    p = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{sig}"


ACCT_PUB = "ACFSDG3ZM7NG52PSJ6QDRYX6RYSLCKDV5UDZWHSDCED6QLWFYZH4EGXT"
OP_PUB = "OCUQANY43FMSJD7E52VJQ3GATODYVA2YJN6NTGIG36HKSO2QIDQQRYTM"


def _reason(fn, *args):
    with pytest.raises(ValissError) as exc:
        fn(*args)
    return exc.value.reason


# --- crash-safety: malformed field types must map to malformed, not raise ---


def test_non_string_iss_is_malformed_not_typeerror():
    tok = _token({"iss": 123, "sub": ACCT_PUB, "valiss": {"type": "account"}})
    assert _reason(token.verify_account, tok, OP_PUB) == "malformed"


def test_huge_exp_is_malformed_not_overflow():
    tok = _token({"iss": OP_PUB, "sub": ACCT_PUB, "exp": 10**30, "valiss": {"type": "account"}})
    assert _reason(token.verify_account, tok, OP_PUB) == "malformed"


@pytest.mark.parametrize(
    "payload",
    [
        {"iss": OP_PUB, "sub": ACCT_PUB, "exp": 1234.5, "valiss": {"type": "account"}},
        {"iss": OP_PUB, "sub": ACCT_PUB, "exp": "1234", "valiss": {"type": "account"}},
        {"iss": OP_PUB, "sub": ACCT_PUB, "valiss": {"type": "account", "epoch": -1}},
        {"iss": OP_PUB, "sub": ACCT_PUB, "valiss": {"type": "account", "epoch": "5"}},
        {"iss": OP_PUB, "sub": ACCT_PUB, "valiss": {"type": "user", "bearer": "yes"}},
        {"iss": OP_PUB, "sub": ACCT_PUB, "valiss": {"type": "account", "ext": "nope"}},
        {"iss": OP_PUB, "sub": ACCT_PUB, "valiss": {"type": "message", "chain": "nope"}},
    ],
)
def test_wrong_field_types_are_malformed(payload):
    assert _reason(token.verify_account, _token(payload), OP_PUB) == "malformed"


def test_null_field_reads_as_absent():
    # A JSON null on an optional field is absent, not malformed (Go leaves the
    # zero value). A null name falls back to the subject, so decode succeeds far
    # enough to reach the issuer/role checks rather than failing malformed.
    tok = _token({"iss": OP_PUB, "sub": ACCT_PUB, "name": None, "valiss": {"type": "account"}})
    # Signature is a dummy, so this fails at signature verification, not decode.
    assert _reason(token.verify_account, tok, OP_PUB) == "bad_signature"


# --- base64url strictness: + and / are not base64url ---


def test_plus_slash_in_token_is_malformed():
    tok = _token({"iss": OP_PUB, "sub": ACCT_PUB, "valiss": {"type": "account"}})
    head, payload, sig = tok.split(".")
    assert _reason(token.verify_account, f"{head}.{payload}.aa+bb", OP_PUB) == "malformed"
    assert _reason(token.verify_account, f"{head}.{payload}.aa/bb", OP_PUB) == "malformed"


# --- request timestamp strictness matches Go RFC3339Nano ---


def test_non_rfc3339_timestamp_is_skew():
    user = nkeys.create_user()
    ctx = b"http\nGET\napi\n/x\n"
    _, sig = token.sign_request(user, ctx, NOW)
    # Space separator instead of 'T' — fromisoformat would accept it, Go does
    # not; it must map to skew, not slip through to a signature check.
    assert (
        _reason(token.verify_signature, user.public_key, "2026-07-10 12:00:00+00:00", sig, ctx, NOW)
        == "skew"
    )
    # Offset without a colon.
    assert (
        _reason(token.verify_signature, user.public_key, "2026-07-10T12:00:00+0000", sig, ctx, NOW)
        == "skew"
    )


# --- huge wire version is malformed (Go int overflow), not unsupported ---


def test_huge_header_version_is_malformed():
    tok = _token({"iss": OP_PUB, "sub": ACCT_PUB, "valiss": {"type": "account"}},
                 header={"typ": "JWT", "alg": "ed25519-nkey", "ver": 10**26})
    assert _reason(token.verify_account, tok, OP_PUB) == "malformed"


# --- creds line splitting matches Go strings.Lines (only \n) ---


def test_creds_payload_with_control_char_is_one_line():
    # A form-feed inside a payload line must not split it (Go splits only on
    # \n). splitlines() would have broken it into two lines -> malformed.
    body = (
        "VALISS-CREDS-VERSION: 1\n"
        "-----BEGIN VALISS ACCOUNT TOKEN-----\n"
        "AAAA\x0cBBBB\n"
        "------END VALISS ACCOUNT TOKEN------\n"
    )
    parsed = creds.parse(body)
    assert parsed.account_token == "AAAA\x0cBBBB"


def test_creds_unicode_or_underscore_version_is_malformed():
    for value in ["1_0", "١"]:  # underscore-grouped, Arabic-Indic digit
        body = (
            f"VALISS-CREDS-VERSION: {value}\n"
            "-----BEGIN VALISS ACCOUNT TOKEN-----\nx.y.z\n------END VALISS ACCOUNT TOKEN------\n"
        )
        assert _reason(creds.parse, body) == "malformed"


# --- validity-window arithmetic must not overflow near datetime bounds ---


def test_window_checks_do_not_overflow_near_datetime_max():
    # An exp within the representable range but near datetime.max must not raise
    # OverflowError when the skew slack is applied.
    c = token.Claims(
        expires_at=datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
        not_before=datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
    )
    assert c.expired(NOW) is False
    assert c.not_yet_valid(NOW) is True
