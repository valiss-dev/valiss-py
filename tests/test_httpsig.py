"""Port of valiss-go contrib/httpsig: the message-token (proof-of-origin) HTTP
transport — client mint + server verify with chain negotiation.

Server-middleware behavior is asserted against both adapters (Django and ASGI)
through one driver fixture; the client Transport and the full negotiation dance
(chainless token → valiss-chain: required → retransmit, chain cache) run
end-to-end through Starlette's TestClient with the real httpx Transport, the one
harness that exercises both sides. Time is injected via now=/at=, never slept.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

import django
from django.conf import settings

if not settings.configured:
    settings.configure(DEBUG=True, ALLOWED_HOSTS=["*"], DEFAULT_CHARSET="utf-8", USE_TZ=True)
    django.setup()

from valiss import creds, httpsig, message, nkeys, token
from valiss.chain import MemoryChainCache
from valiss.keyring import Keyring
from valiss.message import DEFAULT_MESSAGE_TTL

NOW = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)
HOST = "testserver"


def clock(at=NOW):
    return lambda: at


@dataclass
class Chain:
    operator: object
    operator_pub: str
    operator_token: str
    account: object
    user: object
    creds: creds.Creds
    epoch: int


def make_chain(name="prod", epoch=1, *, at=NOW) -> Chain:
    op = nkeys.create_operator()
    ac = nkeys.create_account()
    us = nkeys.create_user()
    op_tok = token.issue_operator(op, name=name, epoch=epoch)
    acct = token.issue_account(op, "acme", ac.public_key, epoch=epoch, ttl=HOUR, now=at)
    usr = token.issue_user(ac, "alice", us.public_key, epoch=epoch, ttl=HOUR, now=at)
    return Chain(
        op, op.public_key, op_tok, ac, us,
        creds.Creds(account_token=acct, user_token=usr, seed=us.seed), epoch,
    )


def mint(chn: Chain, path: str, body: bytes, *, embed_chain=True, epoch=None, at=NOW) -> str:
    return message.issue_message(
        chn.user,
        audience=HOST + path,
        checksum=message.checksum(body),
        ttl=DEFAULT_MESSAGE_TTL,
        epoch=chn.epoch if epoch is None else epoch,
        chain=(chn.creds.account_token, chn.creds.user_token) if embed_chain else None,
        now=at,
    )


# ---------------------------------------------------------------------------
# Server drivers: send a raw request through each framework's middleware and
# report (status, lowercased-header dict, body). The echo handler renders the
# verified claims and the body length, proving both propagation and that the
# body is still readable downstream.
# ---------------------------------------------------------------------------


def _echo(claims, body: bytes) -> str:
    return f"{claims.account.name}|{claims.user.name}|{len(body)}"


class DjangoDriver:
    def __init__(self, **cfg):
        from django.http import HttpResponse
        from django.test import RequestFactory

        from valiss.httpsig.django import message_claims, middleware

        self._rf = RequestFactory()

        def get_response(request):
            return HttpResponse(_echo(message_claims(request), request.body))

        self._handler = middleware(**cfg)(get_response)

    def send(self, method, path, *, body=b"", headers=None):
        hdrs = {**(headers or {}), "Host": HOST}
        request = self._rf.generic(
            method, path, data=body, content_type="application/octet-stream", headers=hdrs
        )
        resp = self._handler(request)
        return resp.status_code, {k.lower(): v for k, v in resp.items()}, resp.content.decode()


class ASGIDriver:
    def __init__(self, **cfg):
        from starlette.requests import Request
        from starlette.testclient import TestClient

        from valiss.httpsig.asgi import Middleware, message_claims

        async def echo_app(scope, receive, send):
            request = Request(scope, receive)
            body = await request.body()
            payload = _echo(message_claims(request), body).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"text/plain; charset=utf-8")],
                }
            )
            await send({"type": "http.response.body", "body": payload})

        app = Middleware(echo_app, **cfg)
        self._client = TestClient(app, base_url=f"http://{HOST}")

    def send(self, method, path, *, body=b"", headers=None):
        resp = self._client.request(method, path, content=body, headers=headers or {})
        return resp.status_code, {k.lower(): v for k, v in resp.headers.items()}, resp.text


@pytest.fixture(params=["django", "asgi"])
def make_driver(request):
    def factory(**cfg):
        return DjangoDriver(**cfg) if request.param == "django" else ASGIDriver(**cfg)

    return factory


# ---------------------------------------------------------------------------
# Parametrized server-middleware tests (Django + ASGI).
# ---------------------------------------------------------------------------


def test_verify_success_propagates_claims_and_body(make_driver):
    chn = make_chain(epoch=1)
    body = b'{"event":"widget.created"}'
    client = make_driver(operator_pub_key=chn.operator_pub, verify_options={"now": NOW})
    tok = mint(chn, "/hook", body)
    status, _, text = client.send("POST", "/hook", body=body, headers={token.HEADER_MESSAGE_TOKEN: tok})
    assert status == 200
    assert text == f"acme|alice|{len(body)}"  # claims propagated, body still readable


def test_missing_token_rejected(make_driver):
    chn = make_chain()
    client = make_driver(operator_pub_key=chn.operator_pub, verify_options={"now": NOW})
    status, _, _ = client.send("POST", "/hook", body=b"x")
    assert status == 401


def test_tampered_body_rejected(make_driver):
    chn = make_chain()
    client = make_driver(operator_pub_key=chn.operator_pub, verify_options={"now": NOW})
    tok = mint(chn, "/hook", b'{"event":"created"}')
    status, _, _ = client.send(
        "POST", "/hook", body=b'{"event":"deleted"}', headers={token.HEADER_MESSAGE_TOKEN: tok}
    )
    assert status == 401


def test_cross_destination_rejected(make_driver):
    chn = make_chain()
    client = make_driver(operator_pub_key=chn.operator_pub, verify_options={"now": NOW})
    body = b"payload"
    tok = mint(chn, "/hook", body)  # bound to /hook
    status, _, _ = client.send("POST", "/other", body=body, headers={token.HEADER_MESSAGE_TOKEN: tok})
    assert status == 401


def test_bodyless_request_round_trips(make_driver):
    chn = make_chain()
    client = make_driver(operator_pub_key=chn.operator_pub, verify_options={"now": NOW})
    tok = mint(chn, "/hook", b"")
    status, _, _ = client.send("GET", "/hook", body=b"", headers={token.HEADER_MESSAGE_TOKEN: tok})
    assert status == 200


def test_operator_policy_stale_epoch_rejected(make_driver):
    chn = make_chain(epoch=1)
    bumped = token.issue_operator(chn.operator, epoch=2)  # a newer domain epoch
    client = make_driver(
        operator_pub_key=chn.operator_pub, verify_options={"now": NOW, "operator_token": bumped}
    )
    tok = mint(chn, "/hook", b"x")
    status, _, _ = client.send("POST", "/hook", body=b"x", headers={token.HEADER_MESSAGE_TOKEN: tok})
    assert status == 401  # epoch 1 message rejected under an epoch-2 domain policy


def test_chainless_without_chain_signals_required(make_driver):
    chn = make_chain()
    client = make_driver(operator_pub_key=chn.operator_pub, verify_options={"now": NOW})
    tok = mint(chn, "/hook", b"x", embed_chain=False)
    status, headers, _ = client.send("POST", "/hook", body=b"x", headers={token.HEADER_MESSAGE_TOKEN: tok})
    assert status == 401
    assert headers.get("valiss-chain") == "required"


def test_detached_chain_verifies(make_driver):
    chn = make_chain()
    client = make_driver(operator_pub_key=chn.operator_pub, verify_options={"now": NOW})
    body = b"payload"
    tok = mint(chn, "/hook", body, embed_chain=False)
    status, _, text = client.send(
        "POST", "/hook", body=body,
        headers={
            token.HEADER_MESSAGE_TOKEN: tok,
            token.HEADER_CHAIN_ACCOUNT_TOKEN: chn.creds.account_token,
            token.HEADER_CHAIN_USER_TOKEN: chn.creds.user_token,
        },
    )
    assert status == 200
    assert text == f"acme|alice|{len(body)}"


def test_detached_chain_tampered_body_is_plain_401(make_driver):
    # A genuine failure (checksum) with a detached chain must not be converted
    # into a chain-required negotiation signal.
    chn = make_chain()
    client = make_driver(operator_pub_key=chn.operator_pub, verify_options={"now": NOW})
    tok = mint(chn, "/hook", b"real", embed_chain=False)
    status, headers, _ = client.send(
        "POST", "/hook", body=b"tampered",
        headers={
            token.HEADER_MESSAGE_TOKEN: tok,
            token.HEADER_CHAIN_ACCOUNT_TOKEN: chn.creds.account_token,
            token.HEADER_CHAIN_USER_TOKEN: chn.creds.user_token,
        },
    )
    assert status == 401
    assert "valiss-chain" not in headers


def test_pinned_chain_config_verifies_chainless(make_driver):
    chn = make_chain()
    client = make_driver(
        operator_pub_key=chn.operator_pub,
        verify_options={"now": NOW, "chain": (chn.creds.account_token, chn.creds.user_token)},
    )
    body = b"x"
    tok = mint(chn, "/hook", body, embed_chain=False)
    status, _, _ = client.send("POST", "/hook", body=body, headers={token.HEADER_MESSAGE_TOKEN: tok})
    assert status == 200


def test_keyring_middleware_verifies_and_segments(make_driver):
    a = make_chain("prod-us", epoch=4)
    b = make_chain("on-prem", epoch=0)
    keyring = Keyring(a.operator_token, b.operator_token)
    client = make_driver(keyring=keyring, verify_options={"now": NOW})

    tok_a = mint(a, "/hook", b"{}")
    status_a, _, text_a = client.send("POST", "/hook", body=b"{}", headers={token.HEADER_MESSAGE_TOKEN: tok_a})
    assert status_a == 200
    assert text_a.startswith("acme|alice")


def test_keyring_middleware_unknown_operator_rejected(make_driver):
    known = make_chain("prod-us", epoch=4)
    stranger = make_chain("stranger", epoch=0)
    keyring = Keyring(known.operator_token)
    client = make_driver(keyring=keyring, verify_options={"now": NOW})
    tok = mint(stranger, "/hook", b"{}")
    status, _, _ = client.send("POST", "/hook", body=b"{}", headers={token.HEADER_MESSAGE_TOKEN: tok})
    assert status == 401


def test_middleware_requires_exactly_one_anchor():
    with pytest.raises(Exception):
        ASGIDriver()  # neither operator_pub_key nor keyring


# ---------------------------------------------------------------------------
# End-to-end client Transport + ASGI middleware: the real httpx auth hook drives
# the negotiation dance against the real middleware.
# ---------------------------------------------------------------------------


class _Counter:
    """Outermost ASGI wrapper: counts HTTP requests reaching the server, so a
    negotiation retransmit is visible as a second request."""

    def __init__(self, app):
        self.app = app
        self.n = 0

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            self.n += 1
        await self.app(scope, receive, send)


def emitter(c, **kwargs):
    """A client Transport pinned to the fixed test clock, so its minted tokens
    fall in the chain's validity window."""
    return httpsig.Transport(c, now=clock(), **kwargs)


def asgi_stack(*, operator_pub_key=None, keyring=None, chain_cache=None, verify_options=None):
    from starlette.requests import Request
    from starlette.testclient import TestClient

    from valiss.httpsig.asgi import Middleware, message_claims

    # Verify at the fixed test instant so the NOW-minted chain is in window.
    verify_options = {"now": NOW, **(verify_options or {})}
    served: list[str] = []

    async def echo_app(scope, receive, send):
        request = Request(scope, receive)
        body = await request.body()
        claims = message_claims(request)
        served.append(f"{claims.operator.name if claims.operator else '-'}/{claims.account.name}")
        assert body == request.scope.get("_expected_body", body)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    counter = _Counter(
        Middleware(
            echo_app, operator_pub_key, keyring=keyring, chain_cache=chain_cache, verify_options=verify_options
        )
    )
    client = TestClient(counter, base_url=f"http://{HOST}")
    return client, counter, served


def test_transport_mint_and_verify_end_to_end():
    chn = make_chain(epoch=1)
    client, _, served = asgi_stack(operator_pub_key=chn.operator_pub)
    payload = b'{"event":"widget.created"}'
    resp = client.post("/hook", content=payload, auth=emitter(chn.creds))
    assert resp.status_code == 200
    assert served == ["-/acme"]  # no operator policy → operator is None


def test_transport_bodyless_get():
    chn = make_chain()
    client, _, _ = asgi_stack(operator_pub_key=chn.operator_pub)
    resp = client.get("/hook", auth=emitter(chn.creds))
    assert resp.status_code == 200


def test_negotiation_cold_then_steady_state():
    chn = make_chain(epoch=1)
    client, counter, served = asgi_stack(
        operator_pub_key=chn.operator_pub, chain_cache=MemoryChainCache()
    )
    auth = emitter(chn.creds, negotiate=True)
    payload = b'{"event":"x"}'

    assert client.post("/hook", content=payload, auth=auth).status_code == 200
    assert counter.n == 2  # cold cache: chainless attempt + chain retransmit
    assert len(served) == 1

    assert client.post("/hook", content=payload, auth=auth).status_code == 200
    assert counter.n == 3  # warm cache: single chainless attempt
    assert len(served) == 2


def test_negotiation_stale_cache_evicted_and_renegotiated():
    chn = make_chain(epoch=1)
    cache = MemoryChainCache()
    client, counter, _ = asgi_stack(operator_pub_key=chn.operator_pub, chain_cache=cache)
    auth = emitter(chn.creds, negotiate=True)
    payload = b"{}"

    # Plant a foreign chain under this emitter's key: verification fails, the
    # entry is dropped, and the retransmit re-establishes the real chain.
    foreign = make_chain(epoch=1)
    emitter_key = token.decode(chn.creds.user_token).subject
    cache.put(emitter_key, foreign.creds.account_token, foreign.creds.user_token)

    before = counter.n
    assert client.post("/hook", content=payload, auth=auth).status_code == 200
    assert counter.n == before + 2  # stale entry: rejected attempt + retransmit

    before = counter.n
    assert client.post("/hook", content=payload, auth=auth).status_code == 200
    assert counter.n == before + 1  # cache healthy again


def test_negotiation_cacheless_receiver_pays_every_time():
    chn = make_chain()
    client, counter, _ = asgi_stack(operator_pub_key=chn.operator_pub)  # no cache
    auth = emitter(chn.creds, negotiate=True)
    before = counter.n
    assert client.post("/hook", content=b"x", auth=auth).status_code == 200
    assert counter.n == before + 2  # every message pays the retransmit without a cache


def test_negotiation_pinned_config_answers_first_attempt():
    chn = make_chain(epoch=0)
    client, counter, _ = asgi_stack(
        operator_pub_key=chn.operator_pub,
        verify_options={"chain": (chn.creds.account_token, chn.creds.user_token)},
    )
    auth = emitter(chn.creds, negotiate=True)
    assert client.post("/hook", content=b"x", auth=auth).status_code == 200
    assert counter.n == 1  # pinned chain answers on the first attempt


def test_keyring_negotiation_segments_by_operator():
    a = make_chain("prod-us", epoch=4)
    b = make_chain("on-prem", epoch=0)
    keyring = Keyring(a.operator_token, b.operator_token)
    client, _, served = asgi_stack(keyring=keyring, chain_cache=MemoryChainCache())

    assert client.post("/hook", content=b"{}", auth=emitter(a.creds, negotiate=True)).status_code == 200
    assert client.post("/hook", content=b"{}", auth=emitter(b.creds, negotiate=True)).status_code == 200
    assert served == ["prod-us/acme", "on-prem/acme"]  # same tenant, segmented by operator


# ---------------------------------------------------------------------------
# Client Transport construction rejections (minter).
# ---------------------------------------------------------------------------


def test_transport_requires_bundle_creds():
    chn = make_chain()
    for broken in (
        creds.Creds(user_token=chn.creds.user_token, seed=chn.creds.seed),
        creds.Creds(account_token=chn.creds.account_token, seed=chn.creds.seed),
        creds.Creds(account_token=chn.creds.account_token, user_token=chn.creds.user_token),
    ):
        with pytest.raises(Exception, match="bundle creds"):
            httpsig.Transport(broken)


def test_transport_chain_epoch_disagreement_rejected():
    op = nkeys.create_operator()
    ac = nkeys.create_account()
    us = nkeys.create_user()
    acct = token.issue_account(op, "acme", ac.public_key, epoch=1, ttl=HOUR, now=NOW)
    usr = token.issue_user(ac, "alice", us.public_key, epoch=2, ttl=HOUR, now=NOW)
    with pytest.raises(Exception, match="chain epochs disagree"):
        httpsig.Transport(creds.Creds(account_token=acct, user_token=usr, seed=us.seed))


def test_transport_non_user_seed_fails_at_mint():
    chn = make_chain()
    account_seed = chn.account.seed
    # minter accepts the account seed; the per-request mint enforces the role.
    transport = httpsig.Transport(
        creds.Creds(account_token=chn.creds.account_token, user_token=chn.creds.user_token, seed=account_seed)
    )
    client, _, _ = asgi_stack(operator_pub_key=chn.operator_pub)
    with pytest.raises(Exception, match="user-type nkey"):
        client.post("/hook", content=b"x", auth=transport)
