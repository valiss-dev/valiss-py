"""Message tokens over gRPC: prove the origin of each request message offline.

The client interceptor mints a fresh proof per unary call, bound to the full
method and the request message's deterministic protobuf bytes; the server
interceptor verifies it against the operator key and hands the claims to the
handler. Like httpsig but for gRPC — it authenticates the message, not a caller;
pair with grpcauth when the caller must also authenticate.

Uses google.protobuf.StringValue as the request/response message, so no .proto
compilation is needed, over an insecure local channel (the token rides metadata).

    uv run --group dev examples/grpc_webhook.py
"""

from concurrent import futures
from datetime import timedelta

import grpc
from google.protobuf.wrappers_pb2 import StringValue

from valiss import creds, grpcsig, message, nkeys, token

METHOD = "/example.v1.Events/Emit"


class EventsHandler(grpc.GenericRpcHandler):
    def service(self, handler_call_details):
        return grpc.unary_unary_rpc_method_handler(
            self._emit,
            request_deserializer=StringValue.FromString,
            response_serializer=StringValue.SerializeToString,
        )

    def _emit(self, request, context):
        claims = grpcsig.message_from_context()
        return StringValue(value=f"from {claims.account.name}/{claims.user.name}: {request.value}")


def main() -> None:
    operator = nkeys.create_operator()
    account = nkeys.create_account()
    user = nkeys.create_user()
    account_token = token.issue_account(operator, "acme", account.public_key, ttl=timedelta(hours=1))
    user_token = token.issue_user(account, "alice", user.public_key, ttl=timedelta(hours=1))
    emitter = creds.Creds(account_token=account_token, user_token=user_token, seed=user.seed)

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=4),
        interceptors=[grpcsig.unary_server_interceptor(operator.public_key)],
    )
    server.add_generic_rpc_handlers([EventsHandler()])
    port = server.add_insecure_port("localhost:0")
    server.start()

    # --- client: the interceptor mints a proof per call bound to the method +
    # the request message's deterministic bytes. ---
    channel = grpc.intercept_channel(
        grpc.insecure_channel(f"localhost:{port}"), grpcsig.unary_client_interceptor(emitter)
    )
    emit = channel.unary_unary(
        METHOD,
        request_serializer=StringValue.SerializeToString,
        response_deserializer=StringValue.FromString,
    )
    print(f"delivered -> {emit(StringValue(value='widget.created')).value}")

    # A token proves one message. Replay a valid proof against a different
    # message over a bare channel: the checksum no longer matches.
    proof = message.issue_message(
        user,
        audience=METHOD,
        checksum=message.checksum(grpcsig.payload(StringValue(value="widget.created"))),
        ttl=timedelta(seconds=30),
        chain=(account_token, user_token),
    )
    with grpc.insecure_channel(f"localhost:{port}") as raw:
        call = raw.unary_unary(
            METHOD,
            request_serializer=StringValue.SerializeToString,
            response_deserializer=StringValue.FromString,
        )
        try:
            call(StringValue(value="widget.deleted"), metadata=[(token.HEADER_MESSAGE_TOKEN, proof)])
        except grpc.RpcError as exc:
            print(f"tampered  -> {exc.code().name}: {exc.details()}")

    channel.close()
    server.stop(None)


if __name__ == "__main__":
    main()
