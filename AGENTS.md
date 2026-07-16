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

The port is full-parity with the Go reference on both sides of the wire. It
mints tokens (all levels, including bearer and message tokens), attaches
credentials to clients, and verifies requests itself. `valiss.verifier.Verifier`
is the integrated request verifier (chain + allowlist/revocation + epoch policy +
replay + extension enforcement + custom validators), single-anchor or, via
`Verifier.with_keyring` (`valiss.keyring`), multi-operator. The transport
adapters wrap it: `valiss.httpauth` (Django + ASGI middleware), `valiss.grpcauth`
(gRPC interceptor), and the message-token transports `valiss.httpsig` /
`valiss.grpcsig`. Nothing of the scheme remains Go-only except key generation and
production account minting (the Go `valiss` CLI).

The per-token `verify_*` helpers in `valiss.token` stay narrow: they check a
single token's signature/type/issuer for tooling and inspection; the Verifier
composes them, so do not fold chain/allowlist/epoch logic back into them.
`valiss.message.verify_message` remains the full-chain verifier for message
tokens, offline-verifiable by design (operator → account → user → message, no
allowlist).

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
uv sync --all-extras            # venv + all extras (dev adds grpc/httpx/requests/django/starlette/protobuf/pyright)
uv run pytest                   # full suite, including conformance + Go interop
uv run pyright src/valiss       # the type-check gate (strict on pure modules via a file header)
uv run pytest tests/test_conformance.py       # spec-1 vectors only
uv run pytest tests/test_token.py -k bearer   # single file / match
uv run --group dev examples/issue_user.py     # minting + client wiring demo
```

Framework-coupled modules (the httpx/grpc client shims and the Django / Starlette
adapters) are excluded from pyright in `pyproject.toml`; the pure core and pure
transport logic stay checked, opting into strict via a `# pyright: strict` file
header. Keep new pure modules strict.

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
- root package (`verifier.go`) → `valiss.verifier` — `Verifier` (single-anchor;
  `.validator`/`.extension` decorators; `verify`/`__call__`), `Request`,
  `Identity`, `static_account_tokens`. Go functional options become keyword
  args (`skew`, `clock`, `resolver`, `replay_cache`, `operator_token`,
  `validators`, `extension_types`).
- `allowlist.go` → `valiss.allowlist` — `Allowlist` protocol (`in`),
  `StaticAllowlist` (set-like, `.from_file`), `ALLOW_ALL`.
- `replay.go` → `valiss.replay` — `ReplayCache` protocol, `MemoryReplayCache`.
- `keyring.go` / `chain.go` → `valiss.keyring` / `valiss.chain` — `Keyring`
  (multi-operator trust; dedup jti, reject dup `(subject, epoch)` / shared name),
  `ChainCache` protocol + `MemoryChainCache`.
- `creds` → `valiss.creds` — creds file, byte-compatible markers and the
  `VALISS-CREDS-VERSION` line.
- nkeys (vendored subset) → `valiss.nkeys` — base32 + CRC16 encode/decode,
  operator/account/user key pairs over `cryptography` Ed25519.
- `contrib/grpcauth` → `valiss.grpcauth` (package) — `call_credentials` (client),
  the `Authenticator` server interceptor + `identity_from_context`, and the
  `grpc` extension claim (`Ext`, pure in `.extension`).
- `contrib/httpauth` → `valiss.httpauth` (package) — client `credential_headers` /
  `Auth` (httpx) / `RequestsAuth` (requests), the pure `http` extension claim +
  `authorize_ext` (`.extension`), the shared `authenticate` core (`._server`),
  and Django / ASGI server middleware (`.django`, `.asgi`).
- `contrib/httpsig` / `contrib/grpcsig` → `valiss.httpsig` / `valiss.grpcsig` —
  message-token transports (client mint + server verify with chain negotiation);
  httpsig ships both an httpx client (`Transport`) and a requests client
  (`RequestsTransport`, negotiation via a response hook). The transport-agnostic
  minter, trust-anchor binding, and verify-with-negotiation state machine live in
  `valiss._msgtransport`, shared by both; the requests adapters' wire-faithful
  host/path/body derivation lives in `valiss._requests`; grpcsig binds the
  checksum to deterministic protobuf (`.payload`).

There is no CLI here; operator/account credential minting for production
stays with the Go `valiss` CLI. `token.issue_account`/`issue_operator`
exist for tests and self-contained examples.

## Wire-compatibility invariants

Do not change without changing the Go side in lockstep:

- Headers: `valiss-account-token`, `valiss-user-token`, `valiss-timestamp`,
  `valiss-signature`, `valiss-nonce` (gRPC metadata keys and HTTP headers
  alike); message-token transports add `valiss-message-token`, the detached
  `valiss-chain-account-token` / `valiss-chain-user-token`, and the
  `valiss-chain: required` negotiation signal (an HTTP response header / a gRPC
  trailer).
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
- grpcio, httpx, and requests are optional extras; `valiss.token`,
  `valiss.creds`, and `valiss.nkeys` must stay importable with only
  `cryptography` installed.
