"""Conformance runner for the language-neutral valiss spec-1 vectors.

Loads the frozen vectors (``tests/vectors/*.json``, a verbatim copy of
``valiss-dev/spec`` — see that directory's README) and asserts the runner
contract from the spec's ``vectors/README.md``: for each case, invoke the
library entrypoint named by ``op`` with ``input`` + ``args``; on ``expect.ok``
the operation MUST succeed and every field in ``expect.claims`` MUST match;
otherwise it MUST fail and the error MUST map to the spec §7 ``expect.reason``
code (exposed as ``ValissError.reason``).

Set ``VALISS_VECTORS_DIR`` to run against a different copy (e.g. a live
checkout or git submodule of the spec vectors) instead of the vendored one.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from valiss import creds, message, token
from valiss.errors import ValissError

_VECTORS_DIR = Path(os.environ.get("VALISS_VECTORS_DIR") or Path(__file__).parent / "vectors")

_CATEGORY_FILES = ["tokens.json", "signatures.json", "creds.json", "messages.json"]

_DURATION_UNITS = {"s": "seconds", "m": "minutes", "h": "hours"}


def _parse_duration(s: str) -> timedelta:
    """Parse a Go-style duration made of ``<number><unit>`` terms (e.g. ``2m``,
    ``1h30m``); enough for the ``skew`` values the vectors carry."""
    kwargs: dict[str, float] = {}
    for value, unit in re.findall(r"(\d+(?:\.\d+)?)([smh])", s):
        kwargs[_DURATION_UNITS[unit]] = kwargs.get(_DURATION_UNITS[unit], 0.0) + float(value)
    if not kwargs:
        raise ValueError(f"unparsable duration {s!r}")
    return timedelta(**kwargs)


def _parse_time(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _load_cases() -> list[tuple[str, dict]]:
    cases: list[tuple[str, dict]] = []
    for name in _CATEGORY_FILES:
        path = _VECTORS_DIR / name
        if not path.exists():
            continue
        data = json.loads(path.read_text())
        assert data.get("spec") == 1, f"{name}: unexpected spec version {data.get('spec')}"
        for case in data["cases"]:
            cases.append((case["id"], case))
    return cases


_CASES = _load_cases()


def _invoke(case: dict) -> dict:
    """Dispatch a case to its library entrypoint, returning the exposed claims
    (on success) or raising ValissError (on failure)."""
    op = case["op"]
    inp = case.get("input", {})
    args = case.get("args", {})

    if op == "verify_operator":
        c = token.verify_operator(inp["token"], args["operator_pub"])
        return {"subject": c.subject, "name": c.name, "epoch": c.epoch}

    if op == "verify_account":
        c = token.verify_account(inp["token"], args["operator_pub"])
        return {"subject": c.subject, "name": c.name, "epoch": c.epoch}

    if op == "verify_user":
        c = token.verify_user(inp["token"], args["account_pub"])
        return {"subject": c.subject, "name": c.name, "epoch": c.epoch, "bearer": c.bearer}

    if op == "verify_message":
        kwargs: dict = {}
        if "now" in args:
            kwargs["now"] = _parse_time(args["now"])
        if "skew" in args:
            kwargs["skew"] = _parse_duration(args["skew"])
        if "audience" in args:
            kwargs["audience"] = args["audience"]
        if args.get("require_checksum"):
            kwargs["require_checksum"] = True
        if "payload" in args:
            kwargs["payload"] = args["payload"].encode()
        if "chain_account" in args and "chain_user" in args:
            kwargs["chain"] = (args["chain_account"], args["chain_user"])
        if "operator_token" in args:
            kwargs["operator_token"] = args["operator_token"]
        c = message.verify_message(inp["token"], args["operator_pub"], **kwargs)
        return {"subject": c.subject, "audience": c.audience, "checksum": c.checksum, "epoch": c.epoch}

    if op == "verify_signature":
        token.verify_signature(
            args["subject_pub"],
            inp["timestamp"],
            inp["signature"],
            args.get("context", "").encode(),
            _parse_time(args["now"]),
            _parse_duration(args["skew"]),
        )
        return {}

    if op == "parse_creds":
        c = creds.parse(inp["creds"])
        return {
            "has_account": bool(c.account_token),
            "has_user": bool(c.user_token),
            "has_seed": bool(c.seed),
        }

    raise AssertionError(f"unknown op {op!r}")


def test_vectors_present():
    """The vendored (or VALISS_VECTORS_DIR) vectors must be loadable, so a
    misconfigured path fails loudly instead of silently passing zero cases."""
    assert _CASES, f"no conformance vectors found under {_VECTORS_DIR}"


@pytest.mark.parametrize("case", [c for _, c in _CASES], ids=[cid for cid, _ in _CASES])
def test_conformance(case: dict):
    expect = case["expect"]
    if expect["ok"]:
        claims = _invoke(case)
        for key, want in expect.get("claims", {}).items():
            assert key in claims, f"{case['id']}: claim {key!r} not exposed"
            assert claims[key] == want, f"{case['id']}: claim {key!r} = {claims[key]!r}, want {want!r}"
    else:
        with pytest.raises(ValissError) as exc_info:
            _invoke(case)
        assert exc_info.value.reason == expect["reason"], (
            f"{case['id']}: error {str(exc_info.value)!r} mapped to reason "
            f"{exc_info.value.reason!r}, want {expect['reason']!r}"
        )
