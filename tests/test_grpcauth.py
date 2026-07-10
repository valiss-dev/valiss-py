from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import grpc
import pytest
from grpc_health.v1 import health, health_pb2, health_pb2_grpc

from valiss import creds, grpcauth, nkeys, token

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


class _Capture:
    def __init__(self):
        self.metadata = None
        self.error = None

    def __call__(self, metadata, error):
        self.metadata = dict(metadata)
        self.error = error


class _FakeContext:
    service_url = "https://localhost:50051/grpc.health.v1.Health"
    method_name = "Check"


FULL_METHOD = "/grpc.health.v1.Health/Check"


def test_plugin_metadata_signing(user_creds, user):
    plugin = grpcauth._CredentialsPlugin(user_creds, nonce=False, now=lambda: NOW)
    cb = _Capture()
    plugin(_FakeContext(), cb)
    assert cb.error is None
    assert cb.metadata[token.HEADER_ACCOUNT_TOKEN] == user_creds.account_token
    assert cb.metadata[token.HEADER_USER_TOKEN] == user_creds.user_token
    assert token.HEADER_NONCE not in cb.metadata
    token.verify_signature(
        user.public_key,
        cb.metadata[token.HEADER_TIMESTAMP],
        cb.metadata[token.HEADER_SIGNATURE],
        grpcauth.method_context(FULL_METHOD),
        NOW,
    )


def test_plugin_metadata_nonce(user_creds, user):
    plugin = grpcauth._CredentialsPlugin(user_creds, nonce=True, now=lambda: NOW)
    cb = _Capture()
    plugin(_FakeContext(), cb)
    assert cb.error is None
    nonce = cb.metadata[token.HEADER_NONCE]
    token.verify_signature(
        user.public_key,
        cb.metadata[token.HEADER_TIMESTAMP],
        cb.metadata[token.HEADER_SIGNATURE],
        grpcauth.method_context(FULL_METHOD, nonce),
        NOW,
    )


def test_plugin_metadata_bearer(operator, account, user):
    c = creds.Creds(
        account_token=token.issue_account(operator, "acme", account.public_key, ttl=TTL, now=NOW),
        user_token=token.issue_user(
            account, "bob", user.public_key, ttl=TTL, bearer=True, now=NOW
        ),
    )
    cb = _Capture()
    grpcauth._CredentialsPlugin(c, nonce=False, now=None)(_FakeContext(), cb)
    assert cb.error is None
    assert token.HEADER_TIMESTAMP not in cb.metadata
    assert token.HEADER_SIGNATURE not in cb.metadata


class _MetadataCapture(grpc.ServerInterceptor):
    def __init__(self):
        self.metadata: dict[str, str] = {}

    def intercept_service(self, continuation, handler_call_details):
        for key, value in handler_call_details.invocation_metadata:
            self.metadata.setdefault(key, value)
        return continuation(handler_call_details)


def test_call_credentials_end_to_end(user_creds, user):
    capture = _MetadataCapture()
    server = grpc.server(ThreadPoolExecutor(max_workers=2), interceptors=[capture])
    health_pb2_grpc.add_HealthServicer_to_server(health.HealthServicer(), server)
    port = server.add_secure_port("localhost:0", grpc.local_server_credentials())
    server.start()
    try:
        channel_creds = grpc.composite_channel_credentials(
            grpc.local_channel_credentials(),
            grpcauth.call_credentials(user_creds, now=lambda: NOW),
        )
        with grpc.secure_channel(f"localhost:{port}", channel_creds) as channel:
            stub = health_pb2_grpc.HealthStub(channel)
            stub.Check(health_pb2.HealthCheckRequest(), timeout=5)
    finally:
        server.stop(None)
    assert capture.metadata[token.HEADER_ACCOUNT_TOKEN] == user_creds.account_token
    assert capture.metadata[token.HEADER_USER_TOKEN] == user_creds.user_token
    # The server side reconstructs the context from the handler's full
    # method, exactly what the interceptor sees.
    token.verify_signature(
        user.public_key,
        capture.metadata[token.HEADER_TIMESTAMP],
        capture.metadata[token.HEADER_SIGNATURE],
        grpcauth.method_context(FULL_METHOD),
        NOW,
    )


def test_ext_payload():
    ext = grpcauth.Ext(methods=["/example.v1.Widgets/*"])
    assert ext.extension_name() == "grpc"
    assert ext.extension_payload() == {"methods": ["/example.v1.Widgets/*"]}
