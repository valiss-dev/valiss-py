"""HTTP message-token (proof-of-origin) transport for the valiss scheme: a
client that mints a fresh proof per request and — with the ``django`` / ``fastapi``
extras — server middleware that verifies it offline against the operator key.

A message token proves the origin of an exact request body at an exact
destination; it authenticates the message, not a caller, and grants no identity.
Pair with ``valiss.httpauth`` when the caller must also authenticate. Emitting is
the typical webhook-sender case:

    from valiss import creds, httpsig
    import httpx
    client = httpx.Client(auth=httpsig.Transport(creds.load("emitter.creds")))
    client.post("https://receiver.example/hook", json=event)   # httpx extra

``RequestsTransport`` is the requests sibling (``requests`` extra):
``session.auth = httpsig.RequestsTransport(creds.load("emitter.creds"))``.

Server middleware (import the framework submodule explicitly):

    from valiss.httpsig.django import middleware, message_claims   # django extra
    from valiss.httpsig import asgi                                # fastapi extra
"""

from ._client import RequestsTransport, Transport
from ._core import audience

__all__ = ["RequestsTransport", "Transport", "audience"]
