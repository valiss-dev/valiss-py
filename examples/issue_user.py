"""Minting short-lived user credentials from account creds, and wiring the
result into HTTP and gRPC clients. Self-contained: the operator and account
are created in-process to stand in for the creds the valiss CLI ships.

    uv run --group dev examples/issue_user.py
"""

from datetime import timedelta

from valiss import creds, grpcauth, httpauth, nkeys, token


def main() -> None:
    # Stand-in for production setup: the valiss CLI mints account creds
    # (operator-signed account token + account seed) and ships them to the
    # tenant. Everything below needs only that creds file.
    operator = nkeys.create_operator()
    account_kp = nkeys.create_account()
    account_creds = creds.Creds(
        account_token=token.issue_account(
            operator, "acme", account_kp.public_key, ttl=timedelta(hours=24)
        ),
        seed=account_kp.seed,
    )

    # Tenant side: knowing the account token and seed, delegate a
    # short-lived signing user. The user keeps its seed and signs every
    # request; the token binds its public key and an HTTP extension the Go
    # server enforces.
    account = creds.parse(account_creds.format())
    user = nkeys.create_user()
    user_token = token.issue_user(
        account.signer(),
        "alice",
        user.public_key,
        ttl=timedelta(minutes=15),
        extensions=[httpauth.Ext(paths=["/v1/*"])],
    )
    alice = creds.Creds(
        account_token=account.account_token, user_token=user_token, seed=user.seed
    )

    # Bearer variant: the generated key pair's seed is discarded, making the
    # token the sole credential. The server accepts it without per-request
    # signatures, so keep the ttl short and the transport TLS.
    bearer_kp = nkeys.create_user()
    bearer_token = token.issue_user(
        account.signer(),
        "bob",
        bearer_kp.public_key,
        ttl=timedelta(minutes=15),
        bearer=True,
        extensions=[httpauth.Ext(paths=["/v1/status"])],
    )
    bob = creds.Creds(account_token=account.account_token, user_token=bearer_token)

    # HTTP: any client works through credential_headers; httpx takes the
    # Auth hook directly:
    #
    #     client = httpx.Client(auth=httpauth.Auth(alice))
    print("alice signs each request:")
    for key, value in httpauth.credential_headers(alice).items():
        print(f"  {key}: {value[:60]}{'...' if len(value) > 60 else ''}")
    print("bob is a bearer, token only:")
    for key, value in httpauth.credential_headers(bob).items():
        print(f"  {key}: {value[:60]}...")

    # gRPC: compose the call credentials into the channel; gRPC sends them
    # only over secure channels (grpc.local_channel_credentials() for local
    # plaintext-equivalent transports).
    #
    #     channel_creds = grpc.composite_channel_credentials(
    #         grpc.ssl_channel_credentials(), grpcauth.call_credentials(alice))
    #     channel = grpc.secure_channel("api.example.com:443", channel_creds)
    grpcauth.call_credentials(alice)
    print("gRPC call credentials built for alice")


if __name__ == "__main__":
    main()
