from datetime import datetime, timedelta, timezone

import pytest

from valiss import message, nkeys, token
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


@pytest.fixture(scope="module")
def chain(operator, account, user):
    account_tok = token.issue_account(operator, "acme", account.public_key, now=NOW)
    user_tok = token.issue_user(account, "alice", user.public_key, now=NOW)
    return account_tok, user_tok


def test_issue_and_verify_message_round_trip(operator, user, chain):
    account_tok, user_tok = chain
    payload = b"hello world"
    tok = message.issue_message(
        user,
        audience="https://api.example.com/ingest",
        checksum=message.checksum(payload),
        chain=(account_tok, user_tok),
        ttl=timedelta(seconds=30),
        now=NOW,
    )
    claims = message.verify_message(
        tok,
        operator.public_key,
        now=NOW,
        audience="https://api.example.com/ingest",
        payload=payload,
    )
    assert claims.subject == user.public_key
    assert claims.audience == "https://api.example.com/ingest"
    assert claims.checksum == message.checksum(payload)
    assert claims.account.name == "acme"
    assert claims.user.name == "alice"
    assert claims.operator is None  # no operator policy supplied


def test_message_requires_expiry(user, chain):
    account_tok, user_tok = chain
    with pytest.raises(ValissError, match="must carry an expiry"):
        message.issue_message(user, chain=(account_tok, user_tok), now=NOW)


def test_message_must_be_signed_by_user_key(operator, account):
    with pytest.raises(ValissError, match="user-type nkey"):
        message.issue_message(account, ttl=timedelta(seconds=30), now=NOW)


def test_message_checksum_must_be_hex_sha256(user, chain):
    account_tok, user_tok = chain
    with pytest.raises(ValissError, match="lowercase-hex SHA-256"):
        message.issue_message(
            user, checksum="nope", chain=(account_tok, user_tok), ttl=timedelta(seconds=30), now=NOW
        )


def test_chain_supplied_out_of_band(operator, user, chain):
    account_tok, user_tok = chain
    # A chainless message verifies when the chain is supplied out of band.
    tok = message.issue_message(user, ttl=timedelta(seconds=30), now=NOW)
    claims = message.verify_message(
        tok, operator.public_key, now=NOW, chain=(account_tok, user_tok)
    )
    assert claims.user.name == "alice"


def test_no_chain_is_distinct_reason(operator, user):
    tok = message.issue_message(user, ttl=timedelta(seconds=30), now=NOW)
    with pytest.raises(ValissError) as exc:
        message.verify_message(tok, operator.public_key, now=NOW)
    assert exc.value.reason == "no_chain"


def test_wrong_audience_rejected(operator, user, chain):
    account_tok, user_tok = chain
    tok = message.issue_message(
        user, audience="https://api/ingest", chain=(account_tok, user_tok),
        ttl=timedelta(seconds=30), now=NOW,
    )
    with pytest.raises(ValissError) as exc:
        message.verify_message(
            tok, operator.public_key, now=NOW, audience="https://evil/ingest"
        )
    assert exc.value.reason == "wrong_audience"


def test_checksum_mismatch_rejected(operator, user, chain):
    account_tok, user_tok = chain
    tok = message.issue_message(
        user, checksum=message.checksum(b"hello world"), chain=(account_tok, user_tok),
        ttl=timedelta(seconds=30), now=NOW,
    )
    with pytest.raises(ValissError) as exc:
        message.verify_message(tok, operator.public_key, now=NOW, payload=b"different")
    assert exc.value.reason == "checksum_mismatch"


def test_message_not_accepted_as_account_or_user(operator, user, chain):
    account_tok, user_tok = chain
    tok = message.issue_message(
        user, chain=(account_tok, user_tok), ttl=timedelta(seconds=30), now=NOW
    )
    # A message token is a proof, never a credential: the per-token verifiers
    # reject it as the wrong type.
    with pytest.raises(ValissError) as exc:
        token.verify_user(tok, operator.public_key)
    assert exc.value.reason == "wrong_type"
