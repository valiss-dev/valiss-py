from datetime import datetime, timedelta, timezone

import httpx
import pytest
import requests

from valiss import ValissError, creds, httpauth, nkeys, token

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
    headers = httpauth.credential_headers(
        user_creds, "GET", "api.example.com", "/v1/whoami", now=lambda: NOW
    )
    assert headers[token.HEADER_ACCOUNT_TOKEN] == user_creds.account_token
    assert headers[token.HEADER_USER_TOKEN] == user_creds.user_token
    assert token.HEADER_NONCE not in headers
    context = httpauth.request_context("GET", "api.example.com", "/v1/whoami")
    token.verify_signature(
        user.public_key,
        headers[token.HEADER_TIMESTAMP],
        headers[token.HEADER_SIGNATURE],
        context,
        NOW,
    )
    # Bound to the request: a different method fails verification.
    with pytest.raises(ValissError, match="signature verification failed"):
        token.verify_signature(
            user.public_key,
            headers[token.HEADER_TIMESTAMP],
            headers[token.HEADER_SIGNATURE],
            httpauth.request_context("DELETE", "api.example.com", "/v1/whoami"),
            NOW,
        )


def test_credential_headers_nonce(user_creds, user):
    nonce = token.new_nonce()
    headers = httpauth.credential_headers(
        user_creds, "GET", "api.example.com", "/v1/whoami", nonce=nonce, now=lambda: NOW
    )
    assert headers[token.HEADER_NONCE] == nonce
    token.verify_signature(
        user.public_key,
        headers[token.HEADER_TIMESTAMP],
        headers[token.HEADER_SIGNATURE],
        httpauth.request_context("GET", "api.example.com", "/v1/whoami", nonce),
        NOW,
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
    headers = httpauth.credential_headers(c, "GET", "api.example.com", "/", now=lambda: NOW)
    assert token.HEADER_ACCOUNT_TOKEN not in headers
    assert headers[token.HEADER_USER_TOKEN] == c.user_token


def test_httpx_auth_attaches_headers(user_creds, user):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers[token.HEADER_ACCOUNT_TOKEN] == user_creds.account_token
        assert request.headers[token.HEADER_USER_TOKEN] == user_creds.user_token
        # The server reconstructs the context from the incoming request.
        context = httpauth.request_context(
            request.method, request.headers["host"], request.url.path
        )
        token.verify_signature(
            user.public_key,
            request.headers[token.HEADER_TIMESTAMP],
            request.headers[token.HEADER_SIGNATURE],
            context,
            NOW,
        )
        return httpx.Response(200)

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        auth=httpauth.Auth(user_creds, now=lambda: NOW),
    )
    assert client.get("https://api.example.com/v1/whoami").status_code == 200


def test_httpx_auth_nonce(user_creds, user):
    def handler(request: httpx.Request) -> httpx.Response:
        nonce = request.headers[token.HEADER_NONCE]
        context = httpauth.request_context(
            request.method, request.headers["host"], request.url.path, nonce
        )
        token.verify_signature(
            user.public_key,
            request.headers[token.HEADER_TIMESTAMP],
            request.headers[token.HEADER_SIGNATURE],
            context,
            NOW,
        )
        return httpx.Response(200)

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        auth=httpauth.Auth(user_creds, nonce=True, now=lambda: NOW),
    )
    assert client.get("https://api.example.com/v1/whoami").status_code == 200


# ---------------------------------------------------------------------------
# requests auth hook: the requests sibling of the httpx Auth.
# ---------------------------------------------------------------------------


class _EchoAdapter(requests.adapters.BaseAdapter):
    """Terminal adapter: hand the prepared request to a handler returning a
    status code — the requests counterpart of httpx.MockTransport."""

    def __init__(self, handler):
        self._handler = handler

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        response = requests.Response()
        response.status_code = self._handler(request)
        response.request = request
        response.url = request.url
        response.connection = self
        response._content = b""
        return response

    def close(self):
        pass


def _session(handler):
    session = requests.Session()
    session.mount("https://", _EchoAdapter(handler))
    return session


def test_requests_auth_attaches_headers(user_creds, user):
    def handler(request):
        assert request.headers[token.HEADER_ACCOUNT_TOKEN] == user_creds.account_token
        assert request.headers[token.HEADER_USER_TOKEN] == user_creds.user_token
        # The server reconstructs the context from the incoming request; the
        # wire Host for a default-port URL is the bare hostname.
        context = httpauth.request_context(request.method, "api.example.com", "/v1/whoami")
        token.verify_signature(
            user.public_key,
            request.headers[token.HEADER_TIMESTAMP],
            request.headers[token.HEADER_SIGNATURE],
            context,
            NOW,
        )
        return 200

    session = _session(handler)
    auth = httpauth.RequestsAuth(user_creds, now=lambda: NOW)
    assert session.get("https://api.example.com/v1/whoami", auth=auth).status_code == 200


def test_requests_auth_nonce(user_creds, user):
    def handler(request):
        nonce = request.headers[token.HEADER_NONCE]
        context = httpauth.request_context(request.method, "api.example.com", "/v1/whoami", nonce)
        token.verify_signature(
            user.public_key,
            request.headers[token.HEADER_TIMESTAMP],
            request.headers[token.HEADER_SIGNATURE],
            context,
            NOW,
        )
        return 200

    session = _session(handler)
    auth = httpauth.RequestsAuth(user_creds, nonce=True, now=lambda: NOW)
    assert session.get("https://api.example.com/v1/whoami", auth=auth).status_code == 200


def test_requests_auth_bearer(operator, account, user):
    c = creds.Creds(
        account_token=token.issue_account(operator, "acme", account.public_key, ttl=TTL, now=NOW),
        user_token=token.issue_user(
            account, "bob", user.public_key, ttl=TTL, bearer=True, now=NOW
        ),
    )
    request = requests.Request("GET", "https://api.example.com/v1/whoami").prepare()
    httpauth.RequestsAuth(c)(request)
    assert request.headers[token.HEADER_ACCOUNT_TOKEN] == c.account_token
    assert request.headers[token.HEADER_USER_TOKEN] == c.user_token
    assert token.HEADER_TIMESTAMP not in request.headers
    assert token.HEADER_SIGNATURE not in request.headers


@pytest.mark.parametrize(
    ("url", "headers", "host"),
    [
        # a non-default port stays in the wire Host
        ("https://api.example.com:8443/v1/x", None, "api.example.com:8443"),
        # the scheme-default port is omitted from the wire Host
        ("https://api.example.com:443/v1/x", None, "api.example.com"),
        # an explicit Host header outranks the URL
        ("https://127.0.0.1:8443/v1/x", {"Host": "api.internal"}, "api.internal"),
    ],
)
def test_requests_auth_signs_the_wire_host(user_creds, user, url, headers, host):
    request = requests.Request("GET", url, headers=headers).prepare()
    httpauth.RequestsAuth(user_creds, now=lambda: NOW)(request)
    token.verify_signature(
        user.public_key,
        request.headers[token.HEADER_TIMESTAMP],
        request.headers[token.HEADER_SIGNATURE],
        httpauth.request_context("GET", host, "/v1/x"),
        NOW,
    )


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
