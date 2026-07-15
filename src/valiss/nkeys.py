"""Minimal Ed25519 nkeys, wire-compatible with github.com/nats-io/nkeys.

Implements the subset valiss needs: operator (``SO...``/``O...``), account
(``SA...``/``A...``), and user (``SU...``/``U...``) key pairs; base32
encoding with the CRC16 checksum; signing and verification. Seeds and public
keys interchange byte-for-byte with the Go library.
"""

from __future__ import annotations

import base64
import binascii
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import ValissError

# nkey prefix bytes, as in the Go library.
PREFIX_OPERATOR = 14 << 3  # 'O'
PREFIX_ACCOUNT = 0  # 'A'
PREFIX_USER = 20 << 3  # 'U'
PREFIX_SEED = 18 << 3  # 'S'

_PUBLIC_PREFIXES = (PREFIX_OPERATOR, PREFIX_ACCOUNT, PREFIX_USER)


def _crc16(data: bytes) -> int:
    """CRC16/XMODEM (poly 0x1021, init 0), the nkeys checksum."""
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021 if crc & 0x8000 else crc << 1) & 0xFFFF
    return crc


def _b32encode(raw: bytes) -> str:
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _b32decode(encoded: str) -> bytes:
    pad = "=" * (-len(encoded) % 8)
    try:
        return base64.b32decode(encoded + pad)
    except (binascii.Error, ValueError) as exc:
        raise ValissError(f"valiss: invalid nkey encoding: {exc}") from exc


def _encode(prefix: int, body: bytes) -> str:
    raw = bytes([prefix]) + body
    return _b32encode(raw + _crc16(raw).to_bytes(2, "little"))


def _decode(encoded: str) -> bytes:
    raw = _b32decode(encoded)
    if len(raw) < 4:
        raise ValissError("valiss: invalid nkey: too short")
    data, crc = raw[:-2], int.from_bytes(raw[-2:], "little")
    if _crc16(data) != crc:
        raise ValissError("valiss: invalid nkey: checksum mismatch")
    return data


def encode_public(prefix: int, raw_key: bytes) -> str:
    """Render a 32-byte Ed25519 public key as an nkey public key string."""
    if prefix not in _PUBLIC_PREFIXES:
        raise ValissError("valiss: invalid nkey public prefix")
    return _encode(prefix, raw_key)


def encode_seed(public_prefix: int, raw_seed: bytes) -> str:
    """Render a 32-byte Ed25519 seed as an nkey seed string (``S...``)."""
    if public_prefix not in _PUBLIC_PREFIXES:
        raise ValissError("valiss: invalid nkey public prefix")
    b1 = PREFIX_SEED | (public_prefix >> 5)
    b2 = (public_prefix & 31) << 3
    raw = bytes([b1, b2]) + raw_seed
    return _b32encode(raw + _crc16(raw).to_bytes(2, "little"))


def decode_public(encoded: str) -> tuple[int, bytes]:
    """Return (prefix byte, 32-byte Ed25519 public key) of an nkey string."""
    data = _decode(encoded)
    prefix = data[0]
    if prefix not in _PUBLIC_PREFIXES:
        raise ValissError("valiss: not a public nkey")
    return prefix, data[1:]


def decode_seed(encoded: str) -> tuple[int, bytes]:
    """Return (public prefix byte, 32-byte Ed25519 seed) of an nkey seed."""
    data = _decode(encoded)
    if len(data) < 4:
        raise ValissError("valiss: invalid nkey seed: too short")
    if data[0] & 248 != PREFIX_SEED:
        raise ValissError("valiss: not an nkey seed")
    prefix = (data[0] & 7) << 5 | (data[1] & 248) >> 3
    if prefix not in _PUBLIC_PREFIXES:
        raise ValissError("valiss: invalid nkey seed prefix")
    # Guard the 32-byte seed length here (mirroring from_public_key), so a
    # truncated seed with a recomputed CRC fails as a ValissError rather than a
    # raw cryptography.ValueError from Ed25519PrivateKey.from_private_bytes that
    # callers do not catch.
    if len(data) - 2 != 32:
        raise ValissError("valiss: invalid nkey seed length")
    return prefix, data[2:]


def _is_valid_public(encoded: str, prefix: int) -> bool:
    try:
        got, raw = decode_public(encoded)
    except ValissError:
        return False
    return got == prefix and len(raw) == 32


def is_valid_public_operator_key(encoded: str) -> bool:
    return _is_valid_public(encoded, PREFIX_OPERATOR)


def is_valid_public_account_key(encoded: str) -> bool:
    return _is_valid_public(encoded, PREFIX_ACCOUNT)


def is_valid_public_user_key(encoded: str) -> bool:
    return _is_valid_public(encoded, PREFIX_USER)


class KeyPair:
    """An nkey pair. Verify-only when built from a public key."""

    def __init__(self, prefix: int, public_raw: bytes, private: Ed25519PrivateKey | None = None):
        self._prefix = prefix
        self._public_raw = public_raw
        self._private = private

    @property
    def public_key(self) -> str:
        return encode_public(self._prefix, self._public_raw)

    @property
    def seed(self) -> str:
        if self._private is None:
            raise ValissError("valiss: key pair holds no seed")
        return encode_seed(self._prefix, self._private.private_bytes_raw())

    def sign(self, data: bytes) -> bytes:
        if self._private is None:
            raise ValissError("valiss: key pair cannot sign: no seed")
        return self._private.sign(data)

    def verify(self, data: bytes, signature: bytes) -> None:
        try:
            Ed25519PublicKey.from_public_bytes(self._public_raw).verify(signature, data)
        except InvalidSignature as exc:
            raise ValissError("valiss: signature verification failed") from exc


def from_seed(seed: str | bytes) -> KeyPair:
    """Build a signing key pair from an nkey seed string."""
    if isinstance(seed, bytes):
        seed = seed.decode("ascii")
    prefix, raw = decode_seed(seed.strip())
    private = Ed25519PrivateKey.from_private_bytes(raw)
    return KeyPair(prefix, private.public_key().public_bytes_raw(), private)


def from_public_key(encoded: str) -> KeyPair:
    """Build a verify-only key pair from an nkey public key string."""
    prefix, raw = decode_public(encoded)
    if len(raw) != 32:
        raise ValissError("valiss: invalid nkey public key length")
    return KeyPair(prefix, raw)


def _create(prefix: int) -> KeyPair:
    private = Ed25519PrivateKey.from_private_bytes(os.urandom(32))
    return KeyPair(prefix, private.public_key().public_bytes_raw(), private)


def create_operator() -> KeyPair:
    return _create(PREFIX_OPERATOR)


def create_account() -> KeyPair:
    return _create(PREFIX_ACCOUNT)


def create_user() -> KeyPair:
    return _create(PREFIX_USER)
