from datetime import datetime, timedelta, timezone

import httpx
import pytest

from valiss import creds, httpauth, nkeys, token

NOW = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)
TTL = timedelta(minutes=15)


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
def user_creds(operator, account, user):
    return creds.Creds(
        account_token=token.issue_account(operator, "acme", account.public_key, ttl=TTL, now=NOW),
        user_token=token.issue_user(account, "alice", user.public_key, ttl=TTL, now=NOW),
        seed=user.seed,
    )


def test_credential_headers_signing(user_creds, user):
    headers = httpauth.credential_headers(user_creds, now=lambda: NOW)
    assert headers[token.HEADER_ACCOUNT_TOKEN] == user_creds.account_token
    assert headers[token.HEADER_USER_TOKEN] == user_creds.user_token
    token.verify_signature(
        user.public_key, headers[token.HEADER_TIMESTAMP], headers[token.HEADER_SIGNATURE], NOW
    )


def test_credential_headers_bearer(operator, account, user):
    c = creds.Creds(
        account_token=token.issue_account(operator, "acme", account.public_key, ttl=TTL, now=NOW),
        user_token=token.issue_user(
            account, "bob", user.public_key, ttl=TTL, bearer=True, now=NOW
        ),
    )
    headers = httpauth.credential_headers(c)
    assert token.HEADER_TIMESTAMP not in headers
    assert token.HEADER_SIGNATURE not in headers


def test_credential_headers_omit_missing_account_token(user_creds):
    c = creds.Creds(user_token=user_creds.user_token, seed=user_creds.seed)
    headers = httpauth.credential_headers(c, now=lambda: NOW)
    assert token.HEADER_ACCOUNT_TOKEN not in headers
    assert headers[token.HEADER_USER_TOKEN] == c.user_token


def test_httpx_auth_attaches_headers(user_creds, user):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers[token.HEADER_ACCOUNT_TOKEN] == user_creds.account_token
        assert request.headers[token.HEADER_USER_TOKEN] == user_creds.user_token
        token.verify_signature(
            user.public_key,
            request.headers[token.HEADER_TIMESTAMP],
            request.headers[token.HEADER_SIGNATURE],
            NOW,
        )
        return httpx.Response(200)

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        auth=httpauth.Auth(user_creds, now=lambda: NOW),
    )
    assert client.get("https://api.example.com/v1/whoami").status_code == 200


def test_ext_payload_omits_empty_dimensions():
    ext = httpauth.Ext(paths=["/v1/*"])
    assert ext.extension_name() == "http"
    assert ext.extension_payload() == {"paths": ["/v1/*"]}
    full = httpauth.Ext(hosts=["api.example.com"], methods=["GET"], paths=["/v1/*"])
    assert full.extension_payload() == {
        "hosts": ["api.example.com"],
        "methods": ["GET"],
        "paths": ["/v1/*"],
    }


def test_ext_mints_into_token(account, user):
    tok = token.issue_user(
        account, "alice", user.public_key, ttl=TTL,
        extensions=[httpauth.Ext(paths=["/v1/*"])], now=NOW,
    )
    claims = token.verify_user(tok, account.public_key)
    assert claims.ext == {"http": {"paths": ["/v1/*"]}}
