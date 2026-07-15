# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

valiss-py is the Python client for
[valiss-go](https://github.com/valiss-dev/valiss-go) (expected as a sibling
checkout at `../valiss-go`): tenant authentication for gRPC and HTTP services
rooted in Ed25519 nkeys. It implements **wire spec version 1**
([`valiss-dev/spec`](https://github.com/valiss-dev/spec), `SPEC-1.md`) and must
stay wire-compatible with the Go reference (v0.12.0) — creds files, tokens,
request signatures, message tokens, and header names interchange freely, proven
against the shared conformance vectors. `SPEC-1.md` is the normative wire
description; where it and the Go code disagree, the code is canonical.

The port is deliberately partial: it mints tokens (all levels, including
bearer user tokens and message tokens) and attaches credentials to clients.
The full request Verifier — allowlists, epoch policy, extension enforcement,
transport middleware — stays with the Go implementation. The `verify_*`
helpers in `valiss.token` check a single token's signature/type/issuer for
tooling and tests only; do not grow them into a Verifier.
`valiss.message.verify_message` is the one full-chain verifier here, because a
message token is offline-verifiable by design (operator → account → user →
message, no allowlist).

## Wire version and reason codes

Each artifact carries its own version discriminator (`SPEC-1.md` §8), and the
version appears on the wire only as an integer — never in a function or type
name. A version-agnostic reader peeks the header/marker version and dispatches
to a per-version decoder (`token._peek_version` / `_decode_token` /
`_decode_v1`); an unrecognized version is rejected cleanly. Adding a version is
additive: a new `_decode_vN` plus one dispatch case. Every failure in the
verification taxonomy raises `ValissError` with a `reason` set to the spec §7
code (`valiss.errors.Reason`); the conformance runner keys off `reason`, not
message text.

## Commands

```sh
uv sync --all-extras            # set up the venv (dev group installs grpc/httpx)
uv run pytest                   # full suite, including conformance + Go interop
uv run pytest tests/test_conformance.py       # spec-1 vectors only
uv run pytest tests/test_token.py -k bearer   # single file / match
uv run --group dev examples/issue_user.py     # minting + client wiring demo
```

The conformance tests (`tests/test_conformance.py`) run the frozen spec-1
vectors vendored under `tests/vectors/` (a verbatim copy from
`valiss-dev/spec`; see that directory's README). Point `VALISS_VECTORS_DIR` at
a live checkout to run against a different copy. Every positive case must
verify with the expected claims; every negative case must fail with the
matching spec §7 `reason`.

The interop tests (`tests/test_interop.py`) drive `go run` in
`tests/interop/`, which `replace`s the Go module `valiss.dev/valiss` to
`../../../valiss-go`; they skip when the Go toolchain or the sibling
`valiss-go` checkout (or `VALISS_GO_DIR`) is missing. Run both suites after any
change to token encoding, nkeys, creds format, request signing, or message
tokens.

## Architecture

Module map (Go package → Python module):

- root package (`token.go`) → `valiss.token` — `issue_operator`/
  `issue_account`/`issue_user` (Go `IssueOperator`/`IssueAccount`/`IssueUser`;
  issue options become keyword arguments: `name`, `ttl`, `expiry`,
  `not_before`, `epoch`, `bearer`, `extensions`), `sign_request`/
  `verify_signature`, per-token `verify_*` helpers, the version-agnostic
  `_decode_token`/`_peek_version`/`_decode_v1` internals, header constants.
- root package (`message.go`) → `valiss.message` — `issue_message` and the
  full-chain `verify_message` (Go `IssueMessage`/`VerifyMessage`), plus
  `checksum` and `MessageClaims`.
- `creds` → `valiss.creds` — creds file, byte-compatible markers and the
  `VALISS-CREDS-VERSION` line.
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
  `valiss-req-v1\n<RFC3339Nano timestamp>\n<hex sha256(context)>`, base64
  (standard, padded). The `valiss-req-v1\n` prefix is part of the signed
  bytes, so a v1 reconstruction fails closed against any other version. The
  context is the transport's canonical request bytes:
  `http\n<method>\n<host>\n<path>\n<nonce>` for HTTP,
  `grpc\n<full method>\n<nonce>` for gRPC; the nonce is empty unless the
  server runs a replay cache. Verification embeds the raw timestamp string
  as received; Python cannot re-render Go's nanosecond precision.
- Tokens: JWT header exactly `{"typ":"JWT","alg":"ed25519-nkey","ver":1}`,
  base64url unpadded; a verifier reads `ver` before parsing the payload and
  rejects an unrecognized version cleanly (signature always verified).
  Payload field order jti, iat, iss, name, sub, aud, exp, nbf, valiss with
  empty fields omitted; the `valiss` section carries the typed claim body
  (`type` operator/account/user/message, `epoch`, `bearer`, message `aud`/
  `checksum`/`chain`, `ext`); jti = unpadded base32 SHA-256 of the claims
  JSON with jti absent, serialized with Go `encoding/json` HTML-escaping of
  `<` `>` `&` (see `token._go_json`); extension map keys serialize sorted.
- Creds file: a `VALISS-CREDS-VERSION: 1` line checked before the payload
  (absent reads as current); markers `VALISS ACCOUNT TOKEN`, `VALISS USER
  TOKEN`, `VALISS SEED`, including the asymmetric `-----BEGIN` / `------END`
  dashes.

## Conventions

- Error messages are prefixed `valiss:`; everything raises `ValissError`.
- Key levels are strict: operator signs account tokens, account signs user
  tokens, never the reverse. Every token binds a subject key; a bearer
  user token still binds one, the server just accepts it unsigned.
- Tests inject time via the `now=` parameters; prefer that over sleeping.
- grpcio and httpx are optional extras; `valiss.token`, `valiss.creds`, and
  `valiss.nkeys` must stay importable with only `cryptography` installed.
