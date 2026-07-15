# valiss-py

Python client for [valiss-go](https://github.com/valiss-dev/valiss-go)
(**VAL**idator-**ISS**uer): tenant authentication for gRPC and HTTP
services, modeled on NATS operator/account/user credentials. Implements
**wire spec version 1** ([`valiss-dev/spec`](https://github.com/valiss-dev/spec),
`SPEC-1.md`) and is wire-compatible with the Go reference (v0.12.0): creds
files, tokens, request signatures, and message tokens interchange freely
between the two, proven against the shared conformance vectors.

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

## Message tokens

A **message token** is a short-lived, self-signed proof of origin: a user key
binds a payload checksum and a destination (`audience`) and, by embedding its
provenance chain, lets a receiver verify offline with only the operator public
key — no per-request signature, no allowlist. A message token is a *proof*,
never a credential: possession grants nothing, and the request verifier never
accepts one.

```python
from valiss import message

proof = message.issue_message(
    user_kp,                                   # signs over itself (iss == sub)
    audience="https://api.example.com/ingest",
    checksum=message.checksum(body),           # lowercase-hex SHA-256 of the bytes
    chain=(account_token, user_token),         # provenance, for offline verify
    ttl=message.DEFAULT_MESSAGE_TTL,
)

claims = message.verify_message(
    proof, operator_pub,
    audience="https://api.example.com/ingest", payload=body,
)  # walks operator -> account -> user -> message; checks epoch, windows, audience, checksum
```

## Wire version

Tokens, creds files, and request signatures each carry their own version
discriminator (`SPEC-1.md` §8), so a future spec version can coexist with this
one. The current version is 1 and appears on the wire only as an integer: the
`"ver":1` JWT header field, the `VALISS-CREDS-VERSION: 1` creds line, and the
`valiss-req-v1` prefix bound into the signed request bytes. A reader peeks the
version before parsing and dispatches to the matching decoder, rejecting an
unrecognized version cleanly. On failure, `ValissError.reason` carries the spec
§7 reason code the failure reduces to.

## Layout

- `valiss.token` — token minting (operator, account, and user level, with
  ttl/expiry, epoch, bearer, and extension claims), request signing,
  per-token verify helpers for tooling and tests
- `valiss.message` — message tokens (proof-of-origin) and their full-chain
  offline verification
- `valiss.creds` — client creds file (tokens + seed)
- `valiss.nkeys` — minimal Ed25519 nkeys (operator/account/user)
- `valiss.grpcauth` — gRPC call credentials and the `grpc` extension claim
- `valiss.httpauth` — HTTP header building, httpx auth hook, and the
  `http` extension claim

## Example

```sh
uv run --group dev examples/issue_user.py
```

## Conformance and interop

`tests/test_conformance.py` runs the language-neutral spec-1 vectors (a frozen
copy under `tests/vectors/`, from `valiss-dev/spec`) and must pass every case:
positive cases verify with the expected claims, negative cases map to the spec
§7 reason code. `tests/test_interop.py` additionally round-trips real
credentials and message tokens against the Go reference; it needs the Go
toolchain and a sibling `valiss-go` checkout (or `VALISS_GO_DIR`), and skips
otherwise.
