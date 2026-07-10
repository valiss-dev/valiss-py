# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

valiss-py is the Python client for [valiss](https://github.com/mikluko/valiss)
(expected as a sibling checkout at `../valiss`): tenant authentication for
gRPC and HTTP services rooted in Ed25519 nkeys. It must stay wire-compatible
with the Go implementation — creds files, tokens, request signatures, and
header names interchange freely. The Go repository's AGENTS.md describes the
scheme.

The port is deliberately partial: it mints tokens (all levels, including
bearer user tokens) and attaches credentials to clients. Server-side chain
verification — allowlists, epoch policy, extension enforcement, transport
middleware — stays with the Go implementation. The `verify_*` helpers in
`valiss.token` check a single token's signature/type/issuer for tooling and
tests only; do not grow them into a Verifier.

## Commands

```sh
uv sync --all-extras            # set up the venv (dev group installs grpc/httpx)
uv run pytest                   # full suite, including Go interop
uv run pytest tests/test_token.py -k bearer   # single file / match
uv run --group dev examples/issue_user.py     # minting + client wiring demo
```

The interop tests (`tests/test_interop.py`) drive `go run` in
`tests/interop/`, which `replace`s the Go module to `../../../valiss`; they
skip when the Go toolchain or the sibling checkout is missing. Run them
after any change to token encoding, nkeys, creds format, or request signing.

## Architecture

Module map (Go package → Python module):

- root package → `valiss.token` — `issue_operator`/`issue_account`/
  `issue_user` (Go `IssueOperator`/`Issue`/`IssueUser`; issue options become
  keyword arguments: `ttl`, `expiry`, `not_before`, `epoch`, `bearer`,
  `extensions`), `sign_request`/`verify_signature`, per-token `verify_*`
  helpers, header constants.
- `creds` → `valiss.creds` — creds file, byte-compatible markers.
- nkeys (vendored subset) → `valiss.nkeys` — base32 + CRC16 encode/decode,
  operator/account/user key pairs over `cryptography` Ed25519.
- `contrib/grpcauth` → `valiss.grpcauth` — `call_credentials` (client) and
  the `grpc` extension claim (`Ext`). No server interceptor.
- `contrib/httpauth` → `valiss.httpauth` — `credential_headers`, `Auth`
  (httpx hook), and the `http` extension claim (`Ext`). No middleware.

There is no CLI here; operator/account credential minting for production
stays with the Go `valiss` CLI. `token.issue_account`/`issue_operator`
exist for tests and self-contained examples.

## Wire-compatibility invariants

Do not change without changing the Go side in lockstep:

- Headers: `valiss-account-token`, `valiss-user-token`, `valiss-timestamp`,
  `valiss-signature`, `valiss-nonce` (gRPC metadata keys and HTTP headers
  alike).
- Request signature: Ed25519 over
  `<RFC3339Nano timestamp>\n<hex sha256(context)>`, base64 (standard,
  padded). The context is the transport's canonical request bytes:
  `http\n<method>\n<host>\n<path>\n<nonce>` for HTTP,
  `grpc\n<full method>\n<nonce>` for gRPC; the nonce is empty unless the
  server runs a replay cache. Verification embeds the raw timestamp string
  as received; Python cannot re-render Go's nanosecond precision.
- Tokens: JWT header exactly `{"typ":"JWT","alg":"ed25519-nkey"}`,
  base64url unpadded; payload field order jti, iat, iss, name, sub, exp,
  nbf, valiss with empty fields omitted; the `valiss` section carries the
  typed claim body (`type` operator/account/user, `epoch`, `bearer`,
  `ext`); jti = unpadded base32 SHA-256 of the claims JSON with jti absent;
  extension map keys serialize sorted.
- Creds file markers (`VALISS ACCOUNT TOKEN`, `VALISS USER TOKEN`,
  `VALISS SEED`), including the asymmetric `-----BEGIN` / `------END`
  dashes.

## Conventions

- Error messages are prefixed `valiss:`; everything raises `ValissError`.
- Key levels are strict: operator signs account tokens, account signs user
  tokens, never the reverse. Every token binds a subject key; a bearer
  user token still binds one, the server just accepts it unsigned.
- Tests inject time via the `now=` parameters; prefer that over sleeping.
- grpcio and httpx are optional extras; `valiss.token`, `valiss.creds`, and
  `valiss.nkeys` must stay importable with only `cryptography` installed.
