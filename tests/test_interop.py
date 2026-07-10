"""Cross-language interop: Go-minted credentials must verify in Python and
Python-minted credentials must verify in Go. Skipped when the Go toolchain
or the sibling ../valiss checkout is unavailable."""

import json
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from valiss import creds, httpauth, nkeys, token

INTEROP_DIR = Path(__file__).parent / "interop"
VALISS_GO = Path(__file__).parent.parent.parent / "valiss"

pytestmark = pytest.mark.skipif(
    shutil.which("go") is None or not VALISS_GO.is_dir(),
    reason="requires the Go toolchain and a ../valiss checkout",
)


def _run(*args: str, stdin: str | None = None) -> str:
    proc = subprocess.run(
        ["go", "run", ".", *args],
        cwd=INTEROP_DIR,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def test_go_minted_credentials_verify_in_python():
    minted = json.loads(_run("mint"))
    now = datetime.now(timezone.utc)

    account_creds = creds.parse(minted["account_creds"])
    account = token.verify_account(account_creds.account_token, minted["operator_pub"])
    assert account.name == "acme"
    assert account.id == minted["jti"]
    assert not account.expired(now)

    user_creds = creds.parse(minted["user_creds"])
    user = token.verify_user(user_creds.user_token, account.subject)
    assert user.name == "alice"
    assert user.bearer is False
    # The Go-minted seed signs in Python and verifies against the token's
    # bound key.
    context = httpauth.request_context("GET", "api.example.com", "/v1/whoami")
    timestamp, signature = token.sign_request(user_creds.signer(), context, now)
    token.verify_signature(user.subject, timestamp, signature, context, now)

    bearer_creds = creds.parse(minted["bearer_creds"])
    bearer = token.verify_user(bearer_creds.user_token, account.subject)
    assert bearer.name == "bob"
    assert bearer.bearer is True
    assert bearer_creds.signer() is None
    headers = httpauth.credential_headers(bearer_creds)
    assert token.HEADER_TIMESTAMP not in headers


def test_python_minted_signing_user_verifies_in_go():
    operator = nkeys.create_operator()
    account = nkeys.create_account()
    user = nkeys.create_user()
    now = datetime.now(timezone.utc)

    account_tok = token.issue_account(
        operator, "acme", account.public_key, ttl=timedelta(hours=1), now=now
    )
    jti = token.verify_account(account_tok, operator.public_key).id
    user_tok = token.issue_user(
        account,
        "alice",
        user.public_key,
        ttl=timedelta(minutes=15),
        extensions=[httpauth.Ext(paths=["/v1/*"])],
        now=now,
    )
    user_creds = creds.Creds(account_token=account_tok, user_token=user_tok, seed=user.seed)
    # Signature bound to the request context, plus a nonce as a client
    # talking to a replay-cache server would send. The Go verifier must
    # derive identical payload bytes from the same context.
    nonce = token.new_nonce()
    context = httpauth.request_context("GET", "api.example.com", "/v1/whoami", nonce)
    headers = httpauth.credential_headers(
        user_creds, "GET", "api.example.com", "/v1/whoami", nonce=nonce
    )

    out = json.loads(
        _run(
            "verify",
            stdin=json.dumps(
                {
                    "operator_pub": operator.public_key,
                    "jti": jti,
                    "account_token": headers[token.HEADER_ACCOUNT_TOKEN],
                    "user_token": headers[token.HEADER_USER_TOKEN],
                    "timestamp": headers[token.HEADER_TIMESTAMP],
                    "signature": headers[token.HEADER_SIGNATURE],
                    "context": context.decode(),
                    "nonce": headers[token.HEADER_NONCE],
                }
            ),
        )
    )
    assert out["account"] == "acme"
    assert out["user"] == "alice"
    assert "bearer" not in out
    assert out["user_ext"] == {"http": {"paths": ["/v1/*"]}}


def test_python_minted_bearer_user_verifies_in_go():
    operator = nkeys.create_operator()
    account = nkeys.create_account()
    # Bearer creds carry no seed: the user key pair is discarded after
    # minting, making the token the sole credential.
    user = nkeys.create_user()
    now = datetime.now(timezone.utc)

    account_tok = token.issue_account(
        operator, "acme", account.public_key, ttl=timedelta(hours=1), now=now
    )
    jti = token.verify_account(account_tok, operator.public_key).id
    user_tok = token.issue_user(
        account, "bob", user.public_key, ttl=timedelta(minutes=15), bearer=True, now=now
    )
    bearer_creds = creds.Creds(account_token=account_tok, user_token=user_tok)
    headers = httpauth.credential_headers(bearer_creds)

    out = json.loads(
        _run(
            "verify",
            stdin=json.dumps(
                {
                    "operator_pub": operator.public_key,
                    "jti": jti,
                    "account_token": headers[token.HEADER_ACCOUNT_TOKEN],
                    "user_token": headers[token.HEADER_USER_TOKEN],
                }
            ),
        )
    )
    assert out == {"account": "acme", "user": "bob", "bearer": True}


def test_python_minted_account_credential_verifies_in_go():
    operator = nkeys.create_operator()
    account = nkeys.create_account()
    now = datetime.now(timezone.utc)

    account_tok = token.issue_account(
        operator, "acme", account.public_key, ttl=timedelta(hours=1), now=now
    )
    jti = token.verify_account(account_tok, operator.public_key).id
    context = grpcauth_method_context()
    timestamp, signature = token.sign_request(account, context, now)

    out = json.loads(
        _run(
            "verify",
            stdin=json.dumps(
                {
                    "operator_pub": operator.public_key,
                    "jti": jti,
                    "account_token": account_tok,
                    "timestamp": timestamp,
                    "signature": signature,
                    "context": context.decode(),
                }
            ),
        )
    )
    assert out == {"account": "acme"}


def grpcauth_method_context() -> bytes:
    """gRPC-shaped context without importing grpcauth (grpcio is an extra
    the core interop must not depend on); mirrors grpcauth.method_context."""
    return b"grpc\n/example.v1.WidgetService/CreateWidget\n"
