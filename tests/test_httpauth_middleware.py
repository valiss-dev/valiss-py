"""Port of valiss-go contrib/httpauth/httpauth_test.go, run against both server
adapters — Django and pure ASGI — through one ``driver`` fixture, so the shared
``_server.authenticate`` core is exercised end-to-end in each framework.

Each driver signs the request with the client's ``credential_headers`` (host and
path fixed so the client-side signature matches what the server reconstructs),
sends it through the framework's middleware, and reports ``(status, body)``. The
echo handler writes back the verified identity (``account`` or ``account/user``)
so identity propagation is asserted too. Time is injected via ``now=``/``clock=``,
never slept.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import django
from django.conf import settings

if not settings.configured:
    settings.configure(DEBUG=True, ALLOWED_HOSTS=["*"], DEFAULT_CHARSET="utf-8", USE_TZ=True)
    django.setup()

from valiss import creds, nkeys, token
from valiss.allowlist import ALLOW_ALL, StaticAllowlist
from valiss.httpauth import Ext, credential_headers
from valiss.replay import MemoryReplayCache
from valiss.verifier import Verifier, static_account_tokens

NOW = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)
HOST = "testserver"


def clock(at=NOW):
    return lambda: at


def headers_for(c: creds.Creds, method: str, path: str, *, nonce: str = "", at=NOW) -> dict[str, str]:
    """Client-side credential headers for a request, bound to HOST and the
    request path so the signature matches what the server reconstructs."""
    return credential_headers(c, method, HOST, path, nonce=nonce, now=clock(at))


# ---------------------------------------------------------------------------
# Drivers: send valiss headers through each framework's middleware and report
# (status, body). Both wrap an echo handler that renders the verified identity.
# ---------------------------------------------------------------------------


def _echo_identity(idn) -> str:
    if idn is None:
        return ""
    return idn.account.name + (f"/{idn.user.name}" if idn.user is not None else "")


class DjangoDriver:
    def __init__(self, verifier: Verifier, allow_missing: bool):
        from django.http import HttpResponse
        from django.test import RequestFactory

        from valiss.httpauth.django import identity, middleware

        self._rf = RequestFactory()

        def get_response(request):
            return HttpResponse(_echo_identity(identity(request)))

        self._handler = middleware(verifier, allow_missing_extension=allow_missing)(get_response)

    def send(self, method: str, path: str, *, headers: dict[str, str]) -> tuple[int, str]:
        request = self._rf.generic(method, path, headers={**headers, "Host": HOST})
        resp = self._handler(request)
        return resp.status_code, resp.content.decode()


class ASGIDriver:
    def __init__(self, verifier: Verifier, allow_missing: bool):
        from starlette.requests import Request
        from starlette.testclient import TestClient

        from valiss.httpauth.asgi import Middleware, identity

        async def echo_app(scope, receive, send):
            body = _echo_identity(identity(Request(scope, receive))).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"text/plain; charset=utf-8")],
                }
            )
            await send({"type": "http.response.body", "body": body})

        app = Middleware(echo_app, verifier=verifier, allow_missing_extension=allow_missing)
        self._client = TestClient(app, base_url=f"http://{HOST}")

    def send(self, method: str, path: str, *, headers: dict[str, str]) -> tuple[int, str]:
        resp = self._client.request(method, path, headers=headers)
        return resp.status_code, resp.text


@pytest.fixture(params=["django", "asgi"])
def make_driver(request):
    kind = request.param

    def factory(verifier: Verifier, *, allow_missing: bool = False):
        return DjangoDriver(verifier, allow_missing) if kind == "django" else ASGIDriver(
            verifier, allow_missing
        )

    return factory


@pytest.fixture
def operator():
    return nkeys.create_operator()


@pytest.fixture
def account():
    return nkeys.create_account()


@pytest.fixture
def user():
    return nkeys.create_user()


# ---------------------------------------------------------------------------
# TestMiddlewareTransport: authentication reaches the handler with the identity.
# ---------------------------------------------------------------------------


def test_authenticated_request_reaches_handler(make_driver, operator, account):
    tok = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    # Authentication is the focus; extension enforcement is off.
    client = make_driver(Verifier(operator.public_key, ALLOW_ALL, clock=clock()), allow_missing=True)
    c = creds.Creds(account_token=tok, seed=account.seed)

    status, body = client.send("GET", "/v1/checks", headers=headers_for(c, "GET", "/v1/checks"))
    assert status == 200
    assert body == "acme"


def test_missing_credential_denied(make_driver, operator):
    client = make_driver(Verifier(operator.public_key, ALLOW_ALL, clock=clock()), allow_missing=True)
    status, _ = client.send("GET", "/v1/checks", headers={})
    assert status == 401


# ---------------------------------------------------------------------------
# TestExtEnforcement: fail-closed http extension.
# ---------------------------------------------------------------------------


@pytest.fixture
def strict_client(make_driver, operator):
    """A strict (extension-enforcing) driver over an allow-all verifier."""

    def build():
        return make_driver(Verifier(operator.public_key, ALLOW_ALL, clock=clock()))

    return build


def test_ext_request_inside_allowed(strict_client, operator, account):
    tok = token.issue_account(
        operator, "acme", account.public_key, ttl=HOUR, now=NOW,
        extensions=[Ext(methods=["GET"], paths=["/v1/*"])],
    )
    c = creds.Creds(account_token=tok, seed=account.seed)
    status, _ = strict_client().send("GET", "/v1/checks", headers=headers_for(c, "GET", "/v1/checks"))
    assert status == 200


def test_ext_path_outside_denied(strict_client, operator, account):
    tok = token.issue_account(
        operator, "acme", account.public_key, ttl=HOUR, now=NOW,
        extensions=[Ext(methods=["GET"], paths=["/v1/*"])],
    )
    c = creds.Creds(account_token=tok, seed=account.seed)
    status, _ = strict_client().send("GET", "/admin", headers=headers_for(c, "GET", "/admin"))
    assert status == 403


def test_ext_method_outside_denied(strict_client, operator, account):
    tok = token.issue_account(
        operator, "acme", account.public_key, ttl=HOUR, now=NOW,
        extensions=[Ext(methods=["GET"], paths=["/v1/*"])],
    )
    c = creds.Creds(account_token=tok, seed=account.seed)
    status, _ = strict_client().send("POST", "/v1/checks", headers=headers_for(c, "POST", "/v1/checks"))
    assert status == 403


def test_ext_host_outside_denied(strict_client, operator, account):
    tok = token.issue_account(
        operator, "acme", account.public_key, ttl=HOUR, now=NOW,
        extensions=[Ext(hosts=["api.example.com"])],
    )
    c = creds.Creds(account_token=tok, seed=account.seed)
    status, _ = strict_client().send("GET", "/v1/checks", headers=headers_for(c, "GET", "/v1/checks"))
    assert status == 403


def test_ext_account_clamps_user(strict_client, operator, account, user):
    acct_tok = token.issue_account(
        operator, "acme", account.public_key, ttl=HOUR, now=NOW,
        extensions=[Ext(paths=["/v1/*"])],
    )
    wide = token.issue_user(
        account, "mallory", user.public_key, ttl=HOUR, now=NOW,
        extensions=[Ext(paths=["/admin/*"])],
    )
    c = creds.Creds(account_token=acct_tok, user_token=wide, seed=user.seed)
    status, _ = strict_client().send("GET", "/admin/panel", headers=headers_for(c, "GET", "/admin/panel"))
    assert status == 403  # the user extension cannot escape the account extension


def test_ext_missing_denied_by_default(strict_client, operator, account):
    tok = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    c = creds.Creds(account_token=tok, seed=account.seed)
    status, body = strict_client().send("GET", "/v1/checks", headers=headers_for(c, "GET", "/v1/checks"))
    assert status == 403
    assert "no http extension" in body


def test_ext_zero_value_grants_nothing(strict_client, operator, account):
    tok = token.issue_account(
        operator, "acme", account.public_key, ttl=HOUR, now=NOW, extensions=[Ext()]
    )
    c = creds.Creds(account_token=tok, seed=account.seed)
    status, _ = strict_client().send("GET", "/v1/checks", headers=headers_for(c, "GET", "/v1/checks"))
    assert status == 403


def test_ext_wildcard_grants_everything(strict_client, operator, account):
    tok = token.issue_account(
        operator, "acme", account.public_key, ttl=HOUR, now=NOW, extensions=[Ext(paths=["*"])]
    )
    c = creds.Creds(account_token=tok, seed=account.seed)
    status, _ = strict_client().send("GET", "/anything", headers=headers_for(c, "GET", "/anything"))
    assert status == 200


# ---------------------------------------------------------------------------
# TestBearerTransport: token-only requests.
# ---------------------------------------------------------------------------


def test_bearer_allows_token_only(make_driver, operator, account, user):
    acct_tok = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    bearer = token.issue_user(account, "carol", user.public_key, bearer=True, ttl=HOUR, now=NOW)
    client = make_driver(Verifier(operator.public_key, ALLOW_ALL, clock=clock()), allow_missing=True)
    # Bearer creds carry no seed, so no signature headers.
    c = creds.Creds(account_token=acct_tok, user_token=bearer)
    status, body = client.send("GET", "/", headers=headers_for(c, "GET", "/"))
    assert status == 200
    assert body == "acme/carol"


def test_plain_token_denies_token_only(make_driver, operator, account, user):
    acct_tok = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    plain = token.issue_user(account, "carol", user.public_key, ttl=HOUR, now=NOW)
    client = make_driver(Verifier(operator.public_key, ALLOW_ALL, clock=clock()), allow_missing=True)
    c = creds.Creds(account_token=acct_tok, user_token=plain)
    status, body = client.send("GET", "/", headers=headers_for(c, "GET", "/"))
    assert status == 401
    assert "not a bearer token" in body


# ---------------------------------------------------------------------------
# TestMiddlewareRejections: allowlist, stale signature, cross-path replay.
# ---------------------------------------------------------------------------


def test_token_not_in_allowlist(make_driver, operator, account):
    tok = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    strict = make_driver(
        Verifier(operator.public_key, StaticAllowlist("other"), clock=clock()), allow_missing=True
    )
    c = creds.Creds(account_token=tok, seed=account.seed)
    status, body = strict.send("GET", "/", headers=headers_for(c, "GET", "/"))
    assert status == 401
    assert "not recognized" in body


def test_stale_request_signature(make_driver, operator, account):
    tok = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    client = make_driver(Verifier(operator.public_key, ALLOW_ALL, clock=clock()), allow_missing=True)
    c = creds.Creds(account_token=tok, seed=account.seed)
    # Signed an hour in the past: fails the skew window.
    stale = headers_for(c, "GET", "/", at=NOW - HOUR)
    status, _ = client.send("GET", "/", headers=stale)
    assert status == 401


def test_captured_headers_do_not_replay_against_other_path(make_driver, operator, account):
    tok = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    client = make_driver(Verifier(operator.public_key, ALLOW_ALL, clock=clock()), allow_missing=True)
    c = creds.Creds(account_token=tok, seed=account.seed)
    # Sign GET /a, then replay the exact headers against POST /b: the signature
    # is bound to method and path, so the replay fails.
    captured = headers_for(c, "GET", "/a")
    status, body = client.send("POST", "/b", headers=captured)
    assert status == 401
    assert "signature verification failed" in body


# ---------------------------------------------------------------------------
# TestReplaySuppression: nonce single-use against a cache-enabled server.
# ---------------------------------------------------------------------------


def test_nonce_passes_once_then_replay_rejected(make_driver, operator, account):
    tok = token.issue_account(
        operator, "acme", account.public_key, ttl=HOUR, now=NOW, extensions=[Ext(paths=["*"])]
    )
    verifier = Verifier(
        operator.public_key, ALLOW_ALL, clock=clock(), replay_cache=MemoryReplayCache(clock=clock())
    )
    client = make_driver(verifier)
    c = creds.Creds(account_token=tok, seed=account.seed)
    fixed = headers_for(c, "GET", "/v1/x", nonce=token.new_nonce())

    first_status, _ = client.send("GET", "/v1/x", headers=fixed)
    second_status, _ = client.send("GET", "/v1/x", headers=fixed)
    assert first_status == 200  # first presentation accepted
    assert second_status == 401  # replay rejected


def test_no_nonce_rejected_by_cache_enabled_server(make_driver, operator, account):
    tok = token.issue_account(
        operator, "acme", account.public_key, ttl=HOUR, now=NOW, extensions=[Ext(paths=["*"])]
    )
    verifier = Verifier(
        operator.public_key, ALLOW_ALL, clock=clock(), replay_cache=MemoryReplayCache(clock=clock())
    )
    client = make_driver(verifier)
    c = creds.Creds(account_token=tok, seed=account.seed)
    status, body = client.send("GET", "/v1/x", headers=headers_for(c, "GET", "/v1/x"))
    assert status == 401
    assert "nonce required" in body


# ---------------------------------------------------------------------------
# TestUserChain: user-level creds through the middleware.
# ---------------------------------------------------------------------------


def test_user_chain_delegated_path_allowed(strict_client, operator, account, user):
    acct_tok = token.issue_account(
        operator, "acme", account.public_key, ttl=HOUR, now=NOW, extensions=[Ext(paths=["/v1/*"])]
    )
    user_tok = token.issue_user(
        account, "alice", user.public_key, ttl=HOUR, now=NOW, extensions=[Ext(paths=["/v1/checks"])]
    )
    c = creds.Creds(account_token=acct_tok, user_token=user_tok, seed=user.seed)
    status, body = strict_client().send("GET", "/v1/checks", headers=headers_for(c, "GET", "/v1/checks"))
    assert status == 200
    assert body == "acme/alice"


def test_user_chain_beyond_delegation_denied(strict_client, operator, account, user):
    acct_tok = token.issue_account(
        operator, "acme", account.public_key, ttl=HOUR, now=NOW, extensions=[Ext(paths=["/v1/*"])]
    )
    user_tok = token.issue_user(
        account, "alice", user.public_key, ttl=HOUR, now=NOW, extensions=[Ext(paths=["/v1/checks"])]
    )
    c = creds.Creds(account_token=acct_tok, user_token=user_tok, seed=user.seed)
    status, _ = strict_client().send("GET", "/v1/admin", headers=headers_for(c, "GET", "/v1/admin"))
    assert status == 403


def test_user_only_creds_with_resolver(make_driver, operator, account, user):
    acct_tok = token.issue_account(
        operator, "acme", account.public_key, ttl=HOUR, now=NOW, extensions=[Ext(paths=["/v1/*"])]
    )
    user_tok = token.issue_user(
        account, "alice", user.public_key, ttl=HOUR, now=NOW, extensions=[Ext(paths=["/v1/checks"])]
    )
    resolver = static_account_tokens(acct_tok)
    client = make_driver(
        Verifier(operator.public_key, ALLOW_ALL, clock=clock(), resolver=resolver)
    )
    # User-only creds: the server resolves the account token itself.
    c = creds.Creds(user_token=user_tok, seed=user.seed)
    status, body = client.send("GET", "/v1/checks", headers=headers_for(c, "GET", "/v1/checks"))
    assert status == 200
    assert body == "acme/alice"


def test_user_only_creds_without_resolver_rejected(make_driver, operator, account, user):
    # No account token is configured anywhere: a server without a resolver
    # cannot supply the account token a user-only credential needs.
    user_tok = token.issue_user(
        account, "alice", user.public_key, ttl=HOUR, now=NOW, extensions=[Ext(paths=["/v1/checks"])]
    )
    client = make_driver(Verifier(operator.public_key, ALLOW_ALL, clock=clock()))
    c = creds.Creds(user_token=user_tok, seed=user.seed)
    status, _ = client.send("GET", "/v1/checks", headers=headers_for(c, "GET", "/v1/checks"))
    assert status == 401


# ---------------------------------------------------------------------------
# Framework-native accessors: FastAPI Depends, Django decorator / accessor.
# ---------------------------------------------------------------------------


def test_fastapi_depends_yields_identity(operator, account):
    fastapi = pytest.importorskip("fastapi")
    from starlette.testclient import TestClient

    from valiss import Identity
    from valiss.httpauth.asgi import Middleware, valiss_identity

    tok = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)
    app = fastapi.FastAPI()

    @app.get("/whoami")
    def whoami(idn: Identity = fastapi.Depends(valiss_identity)):
        return {"tenant": idn.account.name}

    app.add_middleware(
        Middleware, verifier=Verifier(operator.public_key, ALLOW_ALL, clock=clock()), allow_missing_extension=True
    )
    client = TestClient(app, base_url=f"http://{HOST}")
    c = creds.Creds(account_token=tok, seed=account.seed)

    resp = client.get("/whoami", headers=headers_for(c, "GET", "/whoami"))
    assert resp.status_code == 200
    assert resp.json() == {"tenant": "acme"}

    # No middleware in front → the dependency raises 401.
    bare = fastapi.FastAPI()

    @bare.get("/whoami")
    def whoami_bare(idn: Identity = fastapi.Depends(valiss_identity)):
        return {"tenant": idn.account.name}

    assert TestClient(bare, base_url=f"http://{HOST}").get("/whoami").status_code == 401


def test_django_valiss_required_and_identity(operator, account):
    from django.http import HttpResponse
    from django.test import RequestFactory

    from valiss.httpauth.django import identity, middleware, valiss_required

    tok = token.issue_account(operator, "acme", account.public_key, ttl=HOUR, now=NOW)

    @valiss_required
    def view(request):
        return HttpResponse(identity(request).account.name)

    handler = middleware(
        Verifier(operator.public_key, ALLOW_ALL, clock=clock()), allow_missing_extension=True
    )(view)
    rf = RequestFactory()
    c = creds.Creds(account_token=tok, seed=account.seed)
    request = rf.generic("GET", "/x", headers={**headers_for(c, "GET", "/x"), "Host": HOST})
    resp = handler(request)
    assert resp.status_code == 200
    assert resp.content.decode() == "acme"

    # The decorator alone (no middleware) returns 401 when identity is absent.
    naked = valiss_required(lambda request: HttpResponse("ok"))
    assert naked(rf.generic("GET", "/x")).status_code == 401
    # identity() is None on a request the middleware never touched.
    assert identity(rf.generic("GET", "/x")) is None
