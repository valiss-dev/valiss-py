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

The file begins with a ``VALISS-CREDS-VERSION`` line that versions the
container only (the tokens inside carry their own wire version). A parser
reads it before the payload and rejects a version it does not implement; an
absent line reads as the current version, since the pre-versioned format is
otherwise identical.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import nkeys
from .errors import Reason, ValissError

# The creds-file container version. It is emitted as a header line and checked
# on parse, independent of the wire version of the tokens the file carries.
_CREDS_VERSION = 1
_CREDS_VERSION_MARKER = "VALISS-CREDS-VERSION:"

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
        """Render the creds file content, beginning with the version line."""
        out = f"{_CREDS_VERSION_MARKER} {_CREDS_VERSION}\n\n"
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
    """Extract the creds from a file's contents. The version line, if present,
    is checked before the payload. Every section is optional on its own, but at
    least one token must be present."""
    _check_version(contents)
    account_token, _ = _between(contents, _ACCOUNT_TOKEN_BEGIN, _ACCOUNT_TOKEN_END, "creds token")
    user_token, _ = _between(contents, _USER_TOKEN_BEGIN, _USER_TOKEN_END, "creds user token")
    if not account_token and not user_token:
        raise ValissError("valiss: creds: no token markers found", reason=Reason.MISSING)
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


def _check_version(contents: str) -> None:
    """Read the creds-format version header and reject a version this parser
    does not implement. An absent header is read as the current version. It is
    checked before the payload, so an incompatible file is rejected cleanly
    rather than mis-parsed."""
    for line in contents.splitlines():
        rest = line.strip()
        if not rest.startswith(_CREDS_VERSION_MARKER):
            continue
        value = rest[len(_CREDS_VERSION_MARKER):].strip()
        try:
            version = int(value)
        except ValueError as exc:
            raise ValissError(
                f"valiss: creds: malformed version {value!r}", reason=Reason.MALFORMED
            ) from exc
        if version != _CREDS_VERSION:
            raise ValissError(
                f"valiss: creds: unsupported version {version}", reason=Reason.UNSUPPORTED_VERSION
            )
        return
    return


def _between(contents: str, begin: str, end: str, what: str) -> tuple[str, bool]:
    """Single non-empty line strictly between a begin and end marker. The
    bool is False when the begin marker is absent. A present section is
    strict: it must hold exactly one payload line followed by the end
    marker. An empty, unclosed, or multi-line section is an error, so a
    truncated or mangled creds file fails here rather than downstream as a
    confusing cryptographic error."""
    inside = False
    payload = ""
    for line in contents.splitlines():
        line = line.strip()
        if line == begin:
            inside = True
        elif not inside:
            continue
        elif line == end:
            if not payload:
                raise ValissError(
                    f'valiss: {what}: no content before "{end}"', reason=Reason.MALFORMED
                )
            return payload, True
        elif not line:
            continue
        elif not payload:
            payload = line
        else:
            raise ValissError(
                f'valiss: {what}: unexpected content in "{begin}" section', reason=Reason.MALFORMED
            )
    if inside:
        raise ValissError(f'valiss: {what}: marker "{begin}" not closed', reason=Reason.MALFORMED)
    return "", False
