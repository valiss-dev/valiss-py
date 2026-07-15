# Vendored conformance vectors

These are a **frozen, verbatim copy** of the language-neutral valiss spec-1
conformance vectors from the spec repository:

- Source: `valiss-dev/spec` — `vectors/*.json`
- Spec: `SPEC-1.md` (wire spec version 1)
- Pinned commit: `06958028e198181cec25dac38193ec100e929192`

`tests/test_conformance.py` loads these files and asserts the runner contract
from the spec's `vectors/README.md`: every positive case verifies and exposes
the expected claims; every negative case fails and maps to the spec §7 reason
code (`ValissError.reason`).

## Why vendored

The vectors are **frozen with the spec version** — a change that alters a
conforming outcome is a new spec version, not an edit. Vendoring a verbatim
copy keeps the conformance suite self-contained and offline (no submodule
init, no network at test time). To re-point the runner at a live checkout or
submodule instead, set `VALISS_VECTORS_DIR` to a directory holding the same
`*.json` files.

## Updating

Do not edit these files by hand. To refresh them for a new spec revision,
re-copy from `valiss-dev/spec/vectors/` and update the pinned commit above.
If a vector ever looks wrong, fix it upstream in the spec repo (it is the
frozen authority); never patch the vendored copy.
