"""Port of valiss-go contrib/grpcsig: the message-token (proof-of-origin) gRPC
transport — client mint + server verify with chain negotiation, checksum bound
to the request's deterministic protobuf encoding.

Runs a real in-process grpc server behind the server interceptor with a generic
StringValue echo handler; the client interceptor rides an intercepted channel, so
mint, verify, the negotiation trailer, and the identity handoff all run
end-to-end. Server-only rejections (cross-method, tampered, operator policy) send
a hand-minted token as raw metadata. Time is injected via now=/at=, never slept.
"""

from __future__ import annotations

from concurrent import futures
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import grpc
import pytest
from google.protobuf.wrappers_pb2 import StringValue

from valiss import creds, grpcsig, message, nkeys, token
from valiss.chain import MemoryChainCache
from valiss.grpcsig import message_from_context, payload, unary_client_interceptor, unary_server_interceptor
from valiss.keyring import Keyring
from valiss.message import DEFAULT_MESSAGE_TTL

NOW = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)


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


def mint(chn: Chain, method: str, req, *, embed_chain=True, at=NOW) -> str:
    return message.issue_message(
        chn.user,
        audience=method,
        checksum=message.checksum(payload(req)),
        ttl=DEFAULT_MESSAGE_TTL,
        epoch=chn.epoch,
        chain=(chn.creds.account_token, chn.creds.user_token) if embed_chain else None,
        now=at,
    )


# --- in-process server harness -------------------------------------------------


def _claims_str() -> str:
    c = message_from_context()
    if c is None:
        return ""
    op = c.operator.name if c.operator is not None else "-"
    return f"{op}/{c.account.name}/{c.user.name}/{c.audience}"


class _EchoHandler(grpc.GenericRpcHandler):
    def service(self, handler_call_details):
        return grpc.unary_unary_rpc_method_handler(
            self._handle,
            request_deserializer=StringValue.FromString,
            response_serializer=StringValue.SerializeToString,
        )

    def _handle(self, request, context):
        return StringValue(value=_claims_str())


class _Counter(grpc.ServerInterceptor):
    def __init__(self):
        self.n = 0

    def intercept_service(self, continuation, handler_call_details):
        self.n += 1
        return continuation(handler_call_details)


@contextmanager
def serve(**cfg):
    counter = _Counter()
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=4),
        interceptors=[counter, unary_server_interceptor(**cfg)],
    )
    server.add_generic_rpc_handlers([_EchoHandler()])
    port = server.add_insecure_port("localhost:0")
    server.start()
    try:
        yield f"localhost:{port}", counter
    finally:
        server.stop(None)


def call_raw(target, method, request, metadata):
    with grpc.insecure_channel(target) as channel:
        try:
            resp = channel.unary_unary(
                method,
                request_serializer=StringValue.SerializeToString,
                response_deserializer=StringValue.FromString,
            )(request, metadata=metadata)
            return grpc.StatusCode.OK, resp.value
        except grpc.RpcError as exc:
            return exc.code(), exc.details()


def call_intercepted(target, method, request, *, c, negotiate=False):
    base = grpc.insecure_channel(target)
    channel = grpc.intercept_channel(
        base, unary_client_interceptor(c, negotiate=negotiate, now=clock())
    )
    try:
        resp = channel.unary_unary(
            method,
            request_serializer=StringValue.SerializeToString,
            response_deserializer=StringValue.FromString,
        )(request)
        return grpc.StatusCode.OK, resp.value
    except grpc.RpcError as exc:
        return exc.code(), exc.details()
    finally:
        base.close()


@pytest.fixture
def req():
    return StringValue(value="widget.created")


# --- TestInterceptors ----------------------------------------------------------


def test_end_to_end_injects_claims(req):
    chn = make_chain(epoch=1)
    with serve(operator_pub_key=chn.operator_pub, verify_options={"now": NOW}) as (target, _):
        code, body = call_intercepted(target, "/svc/Emit", req, c=chn.creds)
    assert code == grpc.StatusCode.OK
    # operator None (no policy), tenant, user, audience=method
    assert body == "-/acme/alice//svc/Emit"


def test_missing_token_rejected(req):
    chn = make_chain()
    with serve(operator_pub_key=chn.operator_pub, verify_options={"now": NOW}) as (target, _):
        code, details = call_raw(target, "/svc/Emit", req, metadata=[])
    assert code == grpc.StatusCode.UNAUTHENTICATED
    assert "missing message token" in details


def test_cross_method_replay_rejected(req):
    chn = make_chain()
    tok = mint(chn, "/svc/Emit", req)  # bound to /svc/Emit
    with serve(operator_pub_key=chn.operator_pub, verify_options={"now": NOW}) as (target, _):
        code, details = call_raw(
            target, "/svc/Other", req, metadata=[(token.HEADER_MESSAGE_TOKEN, tok)]
        )
    assert code == grpc.StatusCode.UNAUTHENTICATED
    assert "audience" in details


def test_tampered_message_rejected(req):
    chn = make_chain()
    tok = mint(chn, "/svc/Emit", req)
    tampered = StringValue(value="widget.deleted")
    with serve(operator_pub_key=chn.operator_pub, verify_options={"now": NOW}) as (target, _):
        code, details = call_raw(
            target, "/svc/Emit", tampered, metadata=[(token.HEADER_MESSAGE_TOKEN, tok)]
        )
    assert code == grpc.StatusCode.UNAUTHENTICATED
    assert "checksum mismatch" in details


def test_operator_policy_enforced(req):
    chn = make_chain(epoch=1)
    bumped = token.issue_operator(chn.operator, epoch=2)
    tok = mint(chn, "/svc/Emit", req)
    with serve(
        operator_pub_key=chn.operator_pub, verify_options={"now": NOW, "operator_token": bumped}
    ) as (target, _):
        code, details = call_raw(
            target, "/svc/Emit", req, metadata=[(token.HEADER_MESSAGE_TOKEN, tok)]
        )
    assert code == grpc.StatusCode.UNAUTHENTICATED
    assert "trust domain epoch 2" in details


# --- deterministic payload + non-proto rejection -------------------------------


def test_payload_deterministic_and_matches_manual():
    msg = StringValue(value="hello")
    assert payload(msg) == msg.SerializeToString(deterministic=True)


def test_payload_rejects_non_proto():
    with pytest.raises(Exception, match="protobuf message"):
        payload("not a proto")


def test_client_interceptor_non_proto_request_fails():
    chn = make_chain()
    interceptor = unary_client_interceptor(chn.creds, now=clock())

    called = False

    def continuation(details, request):
        nonlocal called
        called = True

    from collections import namedtuple

    details = namedtuple("D", ["method", "timeout", "metadata", "credentials", "wait_for_ready", "compression"])(
        "/svc/Emit", None, None, None, None, None
    )
    with pytest.raises(Exception, match="protobuf message"):
        interceptor.intercept_unary_unary(continuation, details, "not a proto")
    assert not called  # failed before reaching the wire


# --- chain negotiation (end-to-end via the intercepted channel) ----------------


def test_negotiation_cold_then_steady_state(req):
    chn = make_chain(epoch=1)
    with serve(
        operator_pub_key=chn.operator_pub, chain_cache=MemoryChainCache(), verify_options={"now": NOW}
    ) as (target, counter):
        code1, _ = call_intercepted(target, "/svc/Emit", req, c=chn.creds, negotiate=True)
        n_after_cold = counter.n
        code2, _ = call_intercepted(target, "/svc/Emit", req, c=chn.creds, negotiate=True)
        n_after_warm = counter.n
    assert code1 == grpc.StatusCode.OK
    assert code2 == grpc.StatusCode.OK
    assert n_after_cold == 2  # cold cache: chainless attempt + chain retransmit
    assert n_after_warm == 3  # warm cache: single chainless attempt


def test_negotiation_cacheless_receiver_pays_every_time(req):
    chn = make_chain()
    with serve(operator_pub_key=chn.operator_pub, verify_options={"now": NOW}) as (target, counter):
        code, _ = call_intercepted(target, "/svc/Emit", req, c=chn.creds, negotiate=True)
        assert counter.n == 2  # every call pays the retransmit without a cache
    assert code == grpc.StatusCode.OK


def test_chainless_without_chain_signals_required(req):
    chn = make_chain()
    tok = mint(chn, "/svc/Emit", req, embed_chain=False)
    with serve(operator_pub_key=chn.operator_pub, verify_options={"now": NOW}) as (target, _):
        code, details = call_raw(
            target, "/svc/Emit", req, metadata=[(token.HEADER_MESSAGE_TOKEN, tok)]
        )
    assert code == grpc.StatusCode.UNAUTHENTICATED
    assert "chain required" in details


def test_keyring_negotiation_segments_by_operator(req):
    a = make_chain("prod-us", epoch=4)
    b = make_chain("on-prem", epoch=0)
    keyring = Keyring(a.operator_token, b.operator_token)
    with serve(keyring=keyring, chain_cache=MemoryChainCache(), verify_options={"now": NOW}) as (target, _):
        code_a, body_a = call_intercepted(target, "/svc/Emit", req, c=a.creds, negotiate=True)
        code_b, body_b = call_intercepted(target, "/svc/Emit", req, c=b.creds, negotiate=True)
    assert code_a == grpc.StatusCode.OK and body_a == "prod-us/acme/alice//svc/Emit"
    assert code_b == grpc.StatusCode.OK and body_b == "on-prem/acme/alice//svc/Emit"


def test_keyring_unknown_operator_rejected(req):
    known = make_chain("prod-us", epoch=4)
    stranger = make_chain("stranger", epoch=0)
    keyring = Keyring(known.operator_token)
    tok = mint(stranger, "/svc/Emit", req)
    with serve(keyring=keyring, verify_options={"now": NOW}) as (target, _):
        code, _ = call_raw(target, "/svc/Emit", req, metadata=[(token.HEADER_MESSAGE_TOKEN, tok)])
    assert code == grpc.StatusCode.UNAUTHENTICATED


# --- client interceptor construction rejections --------------------------------


def test_client_interceptor_requires_bundle_creds():
    chn = make_chain()
    for broken in (
        creds.Creds(user_token=chn.creds.user_token, seed=chn.creds.seed),
        creds.Creds(account_token=chn.creds.account_token, seed=chn.creds.seed),
        creds.Creds(account_token=chn.creds.account_token, user_token=chn.creds.user_token),
    ):
        with pytest.raises(Exception, match="bundle creds"):
            unary_client_interceptor(broken)


def test_server_requires_exactly_one_anchor():
    with pytest.raises(Exception, match="exactly one"):
        unary_server_interceptor()
