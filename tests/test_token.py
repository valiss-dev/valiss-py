import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from valiss import nkeys, token
from valiss.errors import ValissError

NOW = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def operator():
    return nkeys.create_operator()


@pytest.fixture(scope="module")
def account():
    return nkeys.create_account()


@pytest.fixture(scope="module")
def user():
    return nkeys.create_user()


def _payload(tok: str) -> dict:
    chunk = tok.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(chunk + "=" * (-len(chunk) % 4)))


def test_issue_user_round_trip(account, user):
    tok = token.issue_user(account, "alice", user.public_key, ttl=timedelta(minutes=15), now=NOW)
    claims = token.verify_user(tok, account.public_key)
    assert claims.name == "alice"
    assert claims.subject == user.public_key
    assert claims.issuer == account.public_key
    assert claims.bearer is False
    assert claims.expires_at == NOW + timedelta(minutes=15)
    assert claims.issued_at == NOW
    assert claims.id
    assert not claims.expired(NOW + timedelta(minutes=15))
    assert claims.expired(NOW + timedelta(minutes=18))


def test_issue_user_bearer(account, user):
    tok = token.issue_user(
        account, "bob", user.public_key, ttl=timedelta(minutes=5), bearer=True, now=NOW
    )
    claims = token.verify_user(tok, account.public_key)
    assert claims.bearer is True
    assert _payload(tok)["valiss"]["bearer"] is True


def test_issue_user_epoch_and_extensions(account, user):
    tok = token.issue_user(
        account,
        "alice",
        user.public_key,
        ttl=timedelta(minutes=5),
        epoch=3,
        extensions=[token.RawExtension("custom", {"role": "admin"})],
        now=NOW,
    )
    claims = token.verify_user(tok, account.public_key)
    assert claims.epoch == 3
    assert claims.ext == {"custom": {"role": "admin"}}


def test_issue_user_duplicate_extension(account, user):
    with pytest.raises(ValissError, match="duplicate extension"):
        token.issue_user(
            account,
            "alice",
            user.public_key,
            extensions=[token.RawExtension("x", {}), token.RawExtension("x", {})],
        )


def test_issue_user_rejects_wrong_key_levels(operator, account, user):
    with pytest.raises(ValissError, match="account-type nkey"):
        token.issue_user(operator, "alice", user.public_key)
    with pytest.raises(ValissError, match="invalid user public key"):
        token.issue_user(account, "alice", account.public_key)


def test_issue_user_validity_options(account, user):
    with pytest.raises(ValissError, match="mutually exclusive"):
        token.issue_user(
            account, "a", user.public_key, ttl=timedelta(minutes=1), expiry=NOW, now=NOW
        )
    with pytest.raises(ValissError, match="ttl must be positive"):
        token.issue_user(account, "a", user.public_key, ttl=timedelta(0), now=NOW)
    tok = token.issue_user(
        account,
        "a",
        user.public_key,
        expiry=NOW + timedelta(hours=1),
        not_before=NOW + timedelta(minutes=5),
        now=NOW,
    )
    claims = token.verify_user(tok, account.public_key)
    assert claims.expires_at == NOW + timedelta(hours=1)
    assert claims.not_before == NOW + timedelta(minutes=5)
    assert claims.not_yet_valid(NOW)
    assert not claims.not_yet_valid(NOW + timedelta(minutes=6))
    # No expiry option: the token never expires.
    tok = token.issue_user(account, "a", user.public_key, now=NOW)
    assert token.verify_user(tok, account.public_key).expires_at is None


def test_issue_account_round_trip(operator, account):
    tok = token.issue_account(
        operator, "acme", account.public_key, ttl=timedelta(hours=1), now=NOW
    )
    claims = token.verify_account(tok, operator.public_key)
    assert claims.name == "acme"
    assert claims.subject == account.public_key
    assert claims.issuer == operator.public_key


def test_issue_account_rejects_wrong_key_levels(operator, account, user):
    with pytest.raises(ValissError, match="operator-type nkey"):
        token.issue_account(account, "acme", account.public_key)
    with pytest.raises(ValissError, match="invalid tenant public key"):
        token.issue_account(operator, "acme", user.public_key)


def test_issue_operator_round_trip(operator):
    tok = token.issue_operator(operator, epoch=7, now=NOW)
    claims = token.verify_operator(tok, operator.public_key)
    assert claims.subject == operator.public_key
    assert claims.epoch == 7


def test_verify_rejects_wrong_issuer(account, user):
    other = nkeys.create_account()
    tok = token.issue_user(account, "alice", user.public_key, now=NOW)
    with pytest.raises(ValissError, match="not signed by the expected account"):
        token.verify_user(tok, other.public_key)


def test_verify_rejects_wrong_type(operator, account):
    acct_tok = token.issue_account(operator, "acme", account.public_key, now=NOW)
    with pytest.raises(ValissError, match="not a user token"):
        token.verify_user(acct_tok, operator.public_key)


def test_verify_rejects_tampered_token(account, user):
    tok = token.issue_user(account, "alice", user.public_key, now=NOW)
    head, _, sig = tok.split(".")
    doc = _payload(tok)
    doc["name"] = "mallory"
    forged = (
        base64.urlsafe_b64encode(json.dumps(doc, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )
    with pytest.raises(ValissError, match="signature verification failed"):
        token.verify_user(f"{head}.{forged}.{sig}", account.public_key)


def test_decode_and_issuer_of(account, user):
    tok = token.issue_user(account, "alice", user.public_key, now=NOW)
    assert token.issuer_of(tok) == account.public_key
    claims = token.decode(tok)
    assert claims.subject == user.public_key


def _header(tok: str) -> bytes:
    chunk = tok.split(".")[0]
    return base64.urlsafe_b64decode(chunk + "=" * (-len(chunk) % 4))


def test_wire_shape(account, user):
    """Header bytes, payload fields, and jti derivation match the Go wire
    format (spec 1)."""
    tok = token.issue_user(account, "alice", user.public_key, ttl=timedelta(minutes=5), now=NOW)
    # The version-1 header is byte-exact and carries ver=1.
    assert _header(tok) == b'{"typ":"JWT","alg":"ed25519-nkey","ver":1}'
    doc = _payload(tok)
    assert list(doc) == ["jti", "iat", "iss", "name", "sub", "exp", "valiss"]
    assert doc["valiss"] == {"type": "user"}
    unhashed = {k: v for k, v in doc.items() if k != "jti"}
    digest = hashlib.sha256(
        json.dumps(unhashed, separators=(",", ":"), ensure_ascii=False).encode()
    ).digest()
    assert doc["jti"] == base64.b32encode(digest).decode().rstrip("=")


def test_verify_rejects_unsupported_version(account, user):
    """A verifier reads ver before parsing the payload and rejects an
    unrecognized version cleanly, without mis-parsing it."""
    tok = token.issue_user(account, "alice", user.public_key, now=NOW)
    head, payload, sig = tok.split(".")
    bumped = (
        base64.urlsafe_b64encode(b'{"typ":"JWT","alg":"ed25519-nkey","ver":2}')
        .decode()
        .rstrip("=")
    )
    with pytest.raises(ValissError) as exc:
        token.verify_user(f"{bumped}.{payload}.{sig}", account.public_key)
    assert exc.value.reason == "unsupported_version"


def test_jti_html_escapes_like_go(account, user):
    """jti derivation reproduces Go encoding/json HTML-escaping of < > &, so a
    name carrying those characters yields the same content-derived jti."""
    tok = token.issue_user(account, "a<b>&c", user.public_key, ttl=timedelta(minutes=5), now=NOW)
    payload_chunk = tok.split(".")[1]
    payload_bytes = base64.urlsafe_b64decode(payload_chunk + "=" * (-len(payload_chunk) % 4))
    assert b"\\u003c" in payload_bytes  # <
    assert b"\\u003e" in payload_bytes  # >
    assert b"\\u0026" in payload_bytes  # &
    # The escaped serialization round-trips: the token still verifies and the
    # name decodes back to its unescaped form.
    assert token.verify_user(tok, account.public_key).name == "a<b>&c"


def test_request_signature_binds_version_prefix(user):
    """The signed request bytes begin with the v1 version tag, so a v1
    reconstruction fails closed against any other version."""
    context = b"http\nGET\napi.example.com\n/v1/widgets\n"
    timestamp, signature = token.sign_request(user, context, NOW)
    expected = (
        b"valiss-req-v1\n"
        + timestamp.encode()
        + b"\n"
        + hashlib.sha256(context).hexdigest().encode()
    )
    nkeys.from_public_key(user.public_key).verify(expected, base64.b64decode(signature))
    # Reason codes surface on the verify path.
    with pytest.raises(ValissError) as exc:
        token.verify_signature(user.public_key, "not-a-timestamp", signature, context, NOW)
    assert exc.value.reason == "skew"


def test_sign_and_verify_request(user):
    context = b"http\nGET\napi.example.com\n/v1/whoami\n"
    timestamp, signature = token.sign_request(user, context, NOW)
    token.verify_signature(user.public_key, timestamp, signature, context, NOW)
    with pytest.raises(ValissError, match="skew window"):
        token.verify_signature(
            user.public_key, timestamp, signature, context, NOW + timedelta(minutes=5)
        )
    with pytest.raises(ValissError, match="signature verification failed"):
        token.verify_signature(nkeys.create_user().public_key, timestamp, signature, context, NOW)
    # The signature is bound to the request context: different context bytes
    # fail even with a valid timestamp.
    with pytest.raises(ValissError, match="signature verification failed"):
        token.verify_signature(
            user.public_key, timestamp, signature, b"http\nDELETE\napi.example.com\n/v1/all\n", NOW
        )


def test_sign_request_empty_context(user):
    timestamp, signature = token.sign_request(user, now=NOW)
    token.verify_signature(user.public_key, timestamp, signature, now=NOW)


def test_new_nonce():
    a, b = token.new_nonce(), token.new_nonce()
    assert a != b
    assert len(a) == 32
    int(a, 16)
