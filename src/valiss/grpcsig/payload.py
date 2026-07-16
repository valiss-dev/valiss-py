# pyright: strict
"""The canonical byte string a gRPC message token's checksum is bound to: the
request message's deterministic protobuf encoding.

The wire bytes are not available inside interceptors, so both ends re-marshal
deterministically and must run protobuf runtimes that agree on the encoding.
Requires the ``grpcsig`` extra (protobuf).
"""

from __future__ import annotations

from google.protobuf.message import Message

from ..errors import ValissError


def payload(msg: object) -> bytes:
    """Deterministic protobuf encoding of a request message — the checksum
    input. Raises :class:`ValissError` for a non-protobuf message."""
    if not isinstance(msg, Message):
        raise ValissError(
            f"valiss: message checksum requires a protobuf message, got {type(msg).__name__}"
        )
    return msg.SerializeToString(deterministic=True)
