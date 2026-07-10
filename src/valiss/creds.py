"""Client credentials file: the subject's token plus the seed that signs
its requests, in one marker-delimited text file. A creds file is everything
a client needs. File-compatible with the Go valiss/creds package.

Account-level creds hold the operator-signed account token and the account
seed. User-level creds hold the account-signed user token and the user
seed; the server resolves the account token itself. A *bundle* is the kind
of creds that additionally carries the upstream account token, for servers
that do not resolve it. Bearer creds carry tokens only: their holder cannot
sign requests and the server accepts them only when the effective token is
a bearer user token.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import nkeys
from .errors import ValissError

_ACCOUNT_TOKEN_BEGIN = "-----BEGIN VALISS ACCOUNT TOKEN-----"
_ACCOUNT_TOKEN_END = "------END VALISS ACCOUNT TOKEN------"
_USER_TOKEN_BEGIN = "-----BEGIN VALISS USER TOKEN-----"
_USER_TOKEN_END = "------END VALISS USER TOKEN------"
_SEED_BEGIN = "-----BEGIN VALISS SEED-----"
_SEED_END = "------END VALISS SEED------"


@dataclass
class Creds:
    """Parsed content of a creds file."""

    # account_token is the operator-signed account token. User-level creds
    # omit it by default (the server then resolves the account token by
    # other means, like static configuration); a bundle embeds it.
    account_token: str = ""
    # user_token is the account-signed user token; empty in account-level
    # creds.
    user_token: str = ""
    # seed signs requests as the creds' subject: the account seed in
    # account-level creds, the user seed in user-level ones. Empty in bearer
    # creds.
    seed: str = ""

    def signer(self) -> nkeys.KeyPair | None:
        """Key pair from the creds seed; None for bearer creds."""
        if not self.seed:
            return None
        try:
            return nkeys.from_seed(self.seed)
        except ValissError as exc:
            raise ValissError(f"valiss: creds seed: {exc}") from exc

    def format(self) -> str:
        """Render the creds file content."""
        out = ""
        if self.account_token:
            out += f"{_ACCOUNT_TOKEN_BEGIN}\n{self.account_token.strip()}\n{_ACCOUNT_TOKEN_END}\n"
        if self.user_token:
            if self.account_token:
                out += "\n"
            out += f"{_USER_TOKEN_BEGIN}\n{self.user_token.strip()}\n{_USER_TOKEN_END}\n"
        if self.seed:
            out += f"\n{_SEED_BEGIN}\n{self.seed.strip()}\n{_SEED_END}\n"
            out += (
                "\n************************* IMPORTANT *************************\n"
                "Seed lets anyone sign as this identity. Keep it secret.\n"
            )
        return out


def parse(contents: str) -> Creds:
    """Extract the creds from a file's contents. Every section is optional
    on its own, but at least one token must be present."""
    account_token, _ = _between(contents, _ACCOUNT_TOKEN_BEGIN, _ACCOUNT_TOKEN_END, "creds token")
    user_token, _ = _between(contents, _USER_TOKEN_BEGIN, _USER_TOKEN_END, "creds user token")
    if not account_token and not user_token:
        raise ValissError("valiss: creds: no token markers found")
    seed, _ = _between(contents, _SEED_BEGIN, _SEED_END, "creds seed")
    return Creds(account_token=account_token, user_token=user_token, seed=seed)


def load(path: str) -> Creds:
    """Read and parse a creds file."""
    try:
        with open(path, encoding="utf-8") as f:
            raw = f.read()
    except OSError as exc:
        raise ValissError(f"valiss: read creds: {exc}") from exc
    return parse(raw)


def _between(contents: str, begin: str, end: str, what: str) -> tuple[str, bool]:
    """First non-empty line strictly between a begin and end marker. The
    bool is False when the begin marker is absent; a present but empty or
    unclosed section is an error."""
    inside = False
    for line in contents.splitlines():
        line = line.strip()
        if line == begin:
            inside = True
        elif inside and line == end:
            raise ValissError(f'valiss: {what}: no content before "{end}"')
        elif inside and line:
            return line, True
    if inside:
        raise ValissError(f'valiss: {what}: marker "{begin}" not closed')
    return "", False
