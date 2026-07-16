# pyright: strict
"""Wire-faithful request identity for the ``requests`` client adapters: the
host, path, and body bytes a prepared request puts on the wire. Pure logic — no
requests dependency — shared by the ``httpauth`` and ``httpsig`` adapters, which
guard the ``requests`` import themselves.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from .errors import ValissError

_DEFAULT_PORTS = {"http": 80, "https": 443}


def host_path(url: str, host_header: str = "") -> tuple[str, str]:
    """The (host, path) a prepared request is served under, derived as the wire
    carries them: an explicit Host header wins; otherwise the URL's host, keeping
    the port only when it is not the scheme default (http.client omits default
    ports from the Host header it sends). requests guarantees a prepared URL has
    a non-empty path."""
    parts = urlsplit(url)
    path = parts.path or "/"
    if host_header:
        return host_header, path
    host = parts.hostname or ""
    if ":" in host:  # IPv6 literal: the wire Host keeps the brackets
        host = f"[{host}]"
    port = parts.port
    if port is not None and port != _DEFAULT_PORTS.get(parts.scheme):
        host = f"{host}:{port}"
    return host, path


def body_bytes(body: object) -> bytes:
    """The exact body bytes a prepared request sends, for checksum binding.
    ``None`` is an empty body; a ``str`` body is checksummed as UTF-8, the
    encoding urllib3 puts on the wire. A file-like or iterator body streams and
    can be neither checksummed nor replayed — pass bytes instead."""
    if body is None:
        return b""
    if isinstance(body, bytes):
        return body
    if isinstance(body, bytearray):
        return bytes(body)
    if isinstance(body, str):
        return body.encode("utf-8")
    raise ValissError(
        "valiss: message token requires a buffered request body; pass bytes, not a stream"
    )
