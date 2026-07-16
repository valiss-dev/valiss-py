"""HTTP transport for the valiss scheme: client credential attachment, the
``http`` extension claim, and — with the ``django`` / ``fastapi`` extras —
server middleware that verifies the per-request credential and enforces the
extension.

Client and pure API (dependency-free; ``Auth`` needs the ``httpx`` extra,
``RequestsAuth`` the ``requests`` extra):

    from valiss import httpauth
    headers = httpauth.credential_headers(creds, "GET", "api.example.com", "/v1/x")
    client = httpx.Client(auth=httpauth.Auth(creds))          # httpx extra
    session = requests.Session()
    session.auth = httpauth.RequestsAuth(creds)               # requests extra

Server middleware (import the framework submodule explicitly):

    from valiss.httpauth.django import middleware, identity   # django extra
    from valiss.httpauth import asgi                          # fastapi extra
"""

from ._client import Auth, RequestsAuth, credential_headers
from .extension import Ext, authorize_ext, request_context

__all__ = [
    "Auth",
    "Ext",
    "RequestsAuth",
    "authorize_ext",
    "credential_headers",
    "request_context",
]
