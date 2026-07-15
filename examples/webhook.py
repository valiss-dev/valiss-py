"""Message-token webhook: prove the origin of each request body offline.

A message token is a per-message proof of origin — it authenticates the exact
bytes at the exact destination, not a caller, and the receiver verifies it with
only the operator public key (no callback). This is the webhook-emitter case:
the client Transport mints a fresh token per POST bound to the body and URL, and
the ASGI middleware verifies it and hands the claims to the handler.

Runs in-process with Starlette's TestClient, so no ports are opened.

    uv run --group dev examples/webhook.py
"""

from datetime import timedelta

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from valiss import creds, httpsig, message, nkeys, token
from valiss.httpsig.asgi import Middleware, message_claims


def main() -> None:
    # --- issuer setup: an operator-signed account, an account-signed user; the
    # emitter holds all three plus the user seed (a bundle) to sign messages. ---
    operator = nkeys.create_operator()
    account = nkeys.create_account()
    user = nkeys.create_user()
    account_token = token.issue_account(operator, "acme", account.public_key, ttl=timedelta(hours=1))
    user_token = token.issue_user(account, "alice", user.public_key, ttl=timedelta(hours=1))
    emitter = creds.Creds(account_token=account_token, user_token=user_token, seed=user.seed)

    # --- receiver: the middleware verifies each token offline against the
    # operator key; the handler reads the proven origin. ---
    async def hook(request):
        claims = message_claims(request)
        body = await request.body()
        return PlainTextResponse(f"from {claims.account.name}/{claims.user.name}, {len(body)} bytes")

    app = Starlette(routes=[Route("/hook", hook, methods=["POST"])])
    app.add_middleware(Middleware, operator_pub_key=operator.public_key)
    client = TestClient(app, base_url="http://receiver.example")

    # --- emitter: Transport mints a proof per request bound to the body + URL. ---
    payload = b'{"event":"widget.created","id":42}'
    resp = client.post("/hook", content=payload, auth=httpsig.Transport(emitter))
    print(f"delivered -> {resp.status_code} {resp.text}")

    # A token proves one body at one destination. Mint a valid proof for
    # `payload`, then replay it against a tampered body: the checksum no longer
    # matches and the receiver rejects it offline.
    proof = message.issue_message(
        user,
        audience=httpsig.audience("receiver.example", "/hook"),
        checksum=message.checksum(payload),
        ttl=timedelta(seconds=30),
        chain=(account_token, user_token),
    )
    denied = client.post(
        "/hook", content=b'{"event":"widget.deleted"}',
        headers={token.HEADER_MESSAGE_TOKEN: proof},
    )
    print(f"tampered  -> {denied.status_code} {denied.text}")


if __name__ == "__main__":
    main()
