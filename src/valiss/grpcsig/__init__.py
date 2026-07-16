"""gRPC message-token (proof-of-origin) transport for the valiss scheme: a
client interceptor that mints a fresh proof per unary call and a server
interceptor that verifies it offline against the operator key.

A message token proves the origin of an exact request message at an exact method;
it authenticates the message, not a caller, and grants no identity. Pair with
``valiss.grpcauth`` when the caller must also authenticate.

The checksum is bound to the request message's **deterministic protobuf
encoding** — the wire bytes are not visible inside interceptors, so both ends
re-marshal deterministically; keep the protobuf runtimes of emitter and receiver
in step.

    # client
    from valiss import creds, grpcsig
    channel = grpc.intercept_channel(
        base, grpcsig.unary_client_interceptor(creds.load("emitter.creds")))

    # server
    from valiss import grpcsig
    server = grpc.server(
        executor, interceptors=[grpcsig.unary_server_interceptor(op_pub)])
    # in a servicer method:
    claims = grpcsig.message_from_context()

Requires the ``grpcsig`` extra (grpcio + protobuf).
"""

from ._client import unary_client_interceptor
from .interceptor import message_from_context, unary_server_interceptor
from .payload import payload

__all__ = [
    "message_from_context",
    "payload",
    "unary_client_interceptor",
    "unary_server_interceptor",
]
