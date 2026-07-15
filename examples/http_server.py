"""Server-side HTTP middleware: authenticate every request at the transport.

Where verify_request.py drives the Verifier directly, this shows the ASGI
middleware doing it for you — the credential is pulled off the request headers,
verified, its http extension enforced, and the identity handed to the app —
with the matching client attaching the credential. The same middleware works
under any ASGI server (Starlette, FastAPI, Quart); Django has a sibling adapter
in valiss.httpauth.django.

Runs in-process with Starlette's TestClient, so no ports are opened.

    uv run --group dev examples/http_server.py
"""

from datetime import timedelta

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from valiss import ALLOW_ALL, Verifier, creds, httpauth, nkeys, token
from valiss.httpauth.asgi import Middleware, identity


def main() -> None:
    # --- issuer setup: operator pins trust, account delegates to a user. The
    # server enforces the http extension fail-closed, so every token in the
    # chain carries it — the account grants /v1/*, the user the same. ---
    operator = nkeys.create_operator()
    account = nkeys.create_account()
    account_token = token.issue_account(
        operator, "acme", account.public_key,
        ttl=timedelta(hours=1), extensions=[httpauth.Ext(paths=["/v1/*"])],
    )

    user = nkeys.create_user()
    user_token = token.issue_user(
        account, "alice", user.public_key,
        ttl=timedelta(minutes=15), extensions=[httpauth.Ext(paths=["/v1/*"])],
    )

    # --- server: the app reads the verified identity; the middleware guarantees
    # every request that reaches it is authenticated and inside its extension. ---
    async def whoami(request):
        idn = identity(request)
        return PlainTextResponse(f"{idn.account.name}/{idn.user.name}")

    app = Starlette(routes=[Route("/v1/{rest:path}", whoami)])
    app.add_middleware(Middleware, verifier=Verifier(operator.public_key, ALLOW_ALL))

    # --- client: Auth attaches the tokens and a fresh per-request signature
    # bound to the method, host, and path. ---
    client_creds = creds.Creds(
        account_token=account_token, user_token=user_token, seed=user.seed
    )
    client = TestClient(app, base_url="http://api.example.com")

    resp = client.get("/v1/whoami", auth=httpauth.Auth(client_creds))
    print(f"in-scope  GET /v1/whoami -> {resp.status_code} {resp.text}")

    # A path outside the extension is rejected at the transport with 403 — the
    # app never runs.
    denied = client.get("/v2/secret", auth=httpauth.Auth(client_creds))
    print(f"out-of-scope GET /v2/secret -> {denied.status_code} {denied.text.strip()}")


if __name__ == "__main__":
    main()
