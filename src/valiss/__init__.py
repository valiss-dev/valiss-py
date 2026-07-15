"""valiss: client side of the valiss tenant authentication scheme,
wire-compatible with github.com/mikluko/valiss.

Quick start:

    from valiss import creds, httpauth
    c = creds.load("alice.creds")
    client = httpx.Client(auth=httpauth.Auth(c))

    from valiss import grpcauth
    channel_creds = grpc.composite_channel_credentials(
        grpc.ssl_channel_credentials(), grpcauth.call_credentials(c))
    channel = grpc.secure_channel(addr, channel_creds)

Minting short-lived user tokens from an account seed:

    from valiss import creds, nkeys, token
    account = creds.load("acme.creds")
    user = nkeys.create_user()
    user_token = token.issue_user(
        account.signer(), "alice", user.public_key,
        ttl=timedelta(minutes=15), bearer=True)
    bearer = creds.Creds(
        account_token=account.account_token, user_token=user_token)

Submodules mirror the Go package layout: token (mint, request signing,
per-token verify helpers), message (per-message proof-of-origin tokens and
their full-chain verification), creds (creds file), nkeys (Ed25519 nkeys),
httpauth and grpcauth (client transport adapters and their extension
claims). grpcauth requires the ``grpc`` extra; httpauth.Auth requires the
``httpx`` extra.

Server-side request verification lives in verifier (the integrated Verifier:
chain + allowlist/revocation + epoch policy + replay + extension enforcement +
custom validators), backed by allowlist (accepted account-token ids), replay
(nonce suppression), and keyring (multi-operator trust via
``Verifier.with_keyring``); a Python service turns request headers into a
verified Identity without a round-trip to Go.

Tokens, creds files, and request signatures each carry their own wire-format
version. The current version is 1 (SPEC-1.md); it appears on the wire only as
an integer, and a reader dispatches on it so a future version can coexist. On
failure, :class:`ValissError` carries the spec §7 ``reason`` code (see
:class:`Reason`) the failure reduces to.
"""

from .allowlist import ALLOW_ALL, Allowlist, StaticAllowlist
from .errors import Reason, ValissError
from .keyring import Keyring
from .replay import MemoryReplayCache, ReplayCache
from .verifier import Identity, Request, Verifier, static_account_tokens

__all__ = [
    "ALLOW_ALL",
    "Allowlist",
    "Identity",
    "Keyring",
    "MemoryReplayCache",
    "Reason",
    "Request",
    "ReplayCache",
    "StaticAllowlist",
    "Verifier",
    "ValissError",
    "static_account_tokens",
]
