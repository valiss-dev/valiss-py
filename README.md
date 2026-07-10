# valiss-py

Python client for [valiss](https://github.com/mikluko/valiss)
(**VAL**idator-**ISS**uer): tenant authentication for gRPC and HTTP
services, modeled on NATS operator/account/user credentials. Wire-compatible
with the Go implementation: creds files, tokens, and request signatures
interchange freely between the two.

- An **operator** holds an Ed25519 nkey; its public key is the trust anchor.
- The operator signs each **account** (tenant) a time-limited token that
  binds the account's own nkey public key. Issued token ids go in a
  server-side allowlist.
- An account delegates: it signs **user** tokens with its account seed. A
  **bearer** user token authenticates by the token alone, without
  per-request signatures.
- The client **signs every request** with its nkey over a timestamp bound
  to the request context (method/host/path for HTTP, full method for gRPC;
  bearer tokens excepted), so a captured signature cannot authorize a
  different operation. The Go server verifies the chain up to the pinned
  operator key.

This port covers the client side: minting short-lived user tokens from an
account token and seed, and attaching credentials to httpx and gRPC
clients. Chain verification, allowlists, and extension enforcement stay
with the Go server; key generation and account minting stay with the Go
`valiss` CLI.

## Install

```sh
uv add valiss              # core: creds parsing, token minting, request signing
uv add 'valiss[httpx]'     # + httpx auth hook
uv add 'valiss[grpc]'      # + gRPC call credentials
```

## Issue short-lived user tokens

From account creds (operator-signed account token + account seed):

```python
from datetime import timedelta
from valiss import creds, httpauth, nkeys, token

account = creds.load("acme.creds")

# Signing user: keeps its seed, signs every request.
user = nkeys.create_user()
alice = creds.Creds(
    account_token=account.account_token,
    user_token=token.issue_user(
        account.signer(), "alice", user.public_key,
        ttl=timedelta(minutes=15),
        extensions=[httpauth.Ext(paths=["/v1/*"])]),
    seed=user.seed,
)

# Bearer user: the generated seed is discarded, the token is the sole
# credential. Pair with TLS and short ttl.
bearer_kp = nkeys.create_user()
bob = creds.Creds(
    account_token=account.account_token,
    user_token=token.issue_user(
        account.signer(), "bob", bearer_kp.public_key,
        ttl=timedelta(minutes=15), bearer=True),
)
```

Go servers enforce transport extensions fail-closed: mint `httpauth.Ext`
(hosts/methods/paths) or `grpcauth.Ext` (methods) into every token that
must pass an extension-enforcing middleware.

## Client (HTTP)

```python
import httpx
from valiss import creds, httpauth

c = creds.load("alice.creds")
client = httpx.Client(auth=httpauth.Auth(c))
client.get("https://api.example.com/v1/whoami")
```

If the server runs a replay cache, enable per-request nonces:
`httpauth.Auth(c, nonce=True)`. Any other HTTP client works through
`httpauth.credential_headers(c, method, host, path)`; the signature is
bound to those values, so pass the real ones and build a fresh header set
per request.

## Client (gRPC)

```python
import grpc
from valiss import creds, grpcauth

c = creds.load("alice.creds")
channel_creds = grpc.composite_channel_credentials(
    grpc.ssl_channel_credentials(), grpcauth.call_credentials(c))
channel = grpc.secure_channel("api.example.com:443", channel_creds)
```

gRPC sends call credentials only over secure channels; for local plaintext
development compose with `grpc.local_channel_credentials()` instead. The
per-call signature is bound to the called method;
`grpcauth.call_credentials(c, nonce=True)` adds per-call nonces for
replay-cache servers.

## Layout

- `valiss.token` — token minting (operator, account, and user level, with
  ttl/expiry, epoch, bearer, and extension claims), request signing,
  per-token verify helpers for tooling and tests
- `valiss.creds` — client creds file (tokens + seed)
- `valiss.nkeys` — minimal Ed25519 nkeys (operator/account/user)
- `valiss.grpcauth` — gRPC call credentials and the `grpc` extension claim
- `valiss.httpauth` — HTTP header building, httpx auth hook, and the
  `http` extension claim

## Example

```sh
uv run --group dev examples/issue_user.py
```

Tests include a cross-language interop suite (`tests/test_interop.py`) that
round-trips credentials against the Go library; it needs the Go toolchain
and a `../valiss` checkout, and skips otherwise.
