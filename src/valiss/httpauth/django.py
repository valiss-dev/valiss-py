"""Django server middleware for the valiss scheme.

``middleware(verifier)`` returns a Django middleware factory: install it and
every request is authenticated against the verifier and its http extension
enforced before the view runs. The verified :class:`~valiss.verifier.Identity`
is attached as ``request.valiss_identity`` (read it with :func:`identity`), and
:func:`valiss_required` guards a view against a missing one. Unauthenticated
requests get 401, requests outside an extension's bounds 403 — the view never
sees them.

    # settings.py — the middleware is a closure over the verifier, so build it
    # in a small module and reference the callable:
    #   MIDDLEWARE = [..., "myapp.auth.valiss_mw", ...]
    from valiss.httpauth.django import middleware
    from valiss import Verifier, ALLOW_ALL
    valiss_mw = middleware(Verifier(OPERATOR_PUB_KEY, ALLOW_ALL))

    # views.py
    from valiss.httpauth.django import identity
    def whoami(request):
        return HttpResponse(identity(request).account.name)

Requires the ``django`` extra.
"""

from __future__ import annotations

import functools
from collections.abc import Callable

from django.http import HttpRequest, HttpResponse

from ..verifier import Identity, Verifier
from ._server import authenticate

# Django's new-style middleware is a callable ``get_response -> (request ->
# response)``; the factory closes over the verifier so it can sit in the
# MIDDLEWARE list by dotted path.
GetResponse = Callable[[HttpRequest], HttpResponse]


def middleware(
    verifier: Verifier, *, allow_missing_extension: bool = False
) -> Callable[[GetResponse], GetResponse]:
    """Build a Django middleware that authenticates every request against the
    verifier and enforces the tokens' http extensions, fail-closed: tokens
    without the extension are denied unless ``allow_missing_extension`` is set.
    The verified identity is attached as ``request.valiss_identity``.

    Returns the ``get_response``-style callable Django expects; bind it to a
    name in your settings module and list that dotted path in ``MIDDLEWARE``.
    """

    def make(get_response: GetResponse) -> GetResponse:
        def process(request: HttpRequest) -> HttpResponse:
            headers = request.headers
            result = authenticate(
                verifier,
                account_token=headers.get("valiss-account-token", ""),
                user_token=headers.get("valiss-user-token", ""),
                timestamp=headers.get("valiss-timestamp", ""),
                signature=headers.get("valiss-signature", ""),
                nonce=headers.get("valiss-nonce", ""),
                method=request.method or "",
                # The raw Host header is what the client signed and what the
                # extension matches; do not substitute get_host()'s validated
                # form.
                host=headers.get("host", ""),
                path=request.path,
                allow_missing=allow_missing_extension,
            )
            if isinstance(result, tuple):
                status, message = result
                return HttpResponse(message, status=status, content_type="text/plain; charset=utf-8")
            request.valiss_identity = result  # type: ignore[attr-defined]
            return get_response(request)

        return process

    return make


def identity(request: HttpRequest) -> Identity | None:
    """The verified identity the middleware attached, or ``None`` when the
    middleware did not run for this request (e.g. it is not installed)."""
    return getattr(request, "valiss_identity", None)


def valiss_required(view: Callable[..., HttpResponse]) -> Callable[..., HttpResponse]:
    """View decorator asserting the middleware authenticated the request. It
    returns 401 when ``request.valiss_identity`` is absent — a guard for views
    that must not run without the middleware in front of them. With the
    middleware installed the request is already verified, so this only matters
    when it is missing or ordered after the view."""

    @functools.wraps(view)
    def wrapper(request: HttpRequest, *args: object, **kwargs: object) -> HttpResponse:
        if getattr(request, "valiss_identity", None) is None:
            return HttpResponse(
                "valiss: authentication required",
                status=401,
                content_type="text/plain; charset=utf-8",
            )
        return view(request, *args, **kwargs)

    return wrapper
