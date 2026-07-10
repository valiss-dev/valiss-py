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


def test_wire_shape(account, user):
    """Payload fields and jti derivation match the Go wire format."""
    tok = token.issue_user(account, "alice", user.public_key, ttl=timedelta(minutes=5), now=NOW)
    doc = _payload(tok)
    assert list(doc) == ["jti", "iat", "iss", "name", "sub", "exp", "valiss"]
    assert doc["valiss"] == {"type": "user"}
    unhashed = {k: v for k, v in doc.items() if k != "jti"}
    digest = hashlib.sha256(
        json.dumps(unhashed, separators=(",", ":"), ensure_ascii=False).encode()
    ).digest()
    assert doc["jti"] == base64.b32encode(digest).decode().rstrip("=")


def test_sign_and_verify_request(user):
    timestamp, signature = token.sign_request(user, NOW)
    token.verify_signature(user.public_key, timestamp, signature, NOW)
    with pytest.raises(ValissError, match="skew window"):
        token.verify_signature(user.public_key, timestamp, signature, NOW + timedelta(minutes=5))
    with pytest.raises(ValissError, match="signature verification failed"):
        token.verify_signature(nkeys.create_user().public_key, timestamp, signature, NOW)
