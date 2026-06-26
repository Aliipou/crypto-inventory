# crypto-inventory — what it can and cannot detect (honest)

It is a **static** scanner with several source frontends. The Python frontend is
precise (AST, import-level); the others are coarser text/regex signals. It is a
discovery aid, not a proof of quantum-readiness. Do not claim "PQC-ready" from a
clean scan alone.

## Detects

- **Python (AST, precise):** imports of Shor-broken public-key primitives (RSA, DH,
  DSA, EC/ECDSA/ECDH, Ed25519/Ed448, X25519/X448, ElGamal) from `cryptography`,
  `pycryptodome`/`Crypto`, and the standalone `rsa` / `ecdsa` libraries.
- **Dependency manifests:** vulnerable packages declared in `requirements*.txt`,
  `pyproject.toml`, etc.
- **Rust source (regex, coarse):** `use`/path references to the common
  quantum-vulnerable crates (ed25519-dalek, x25519-dalek, rsa, ecdsa, p256/p384/k256,
  dsa, elliptic-curve, ring's `signature` module). Closes the Python-only gap so the
  tool can see crypto like AuthGate's own Rust Ed25519.
- **Certificates / TLS config (coarse):** the *presence* of cert/key files (algorithm
  unverified, flagged MEDIUM) and config files that *name* an RSA/ECDSA/EC/DSA key
  type (flagged HIGH).
- HNDL classification (confidentiality/key-exchange vs. signatures) and the NIST PQC
  replacement.
- Advisory: Grover-weakened symmetric sizes (e.g. AES-128).

## Does NOT detect (known limitations)

- **Non-source crypto.** TLS/SSH negotiated at runtime, HSM/KMS-managed keys, JWT
  alg fields, compiled/vendored binaries. Real inventory still needs network +
  runtime scanners too.
- **Rust matching is regex, not a parse.** The `.rs` frontend keys off `use`/path
  syntax and known crate names — it is NOT a Rust compiler frontend. It will miss
  crypto reached through re-exports, type aliases, macro-generated paths, or crates
  it doesn't know; and it only flags `ring`'s `signature` submodule, not other
  `ring` paths. Same class of blind spot the Python AST scanner has with dynamic
  imports. Block/line comments are stripped at whole-line granularity (a `use` on
  the same line as the start of a `/* */` block could be missed).
- **Certificate / config detection is coarse, both directions.** A flagged cert/key
  file only means *a file with that suffix exists*; its actual algorithm is
  unverified (could already be PQC) — hence MEDIUM and "verify". A config finding
  only means the text *mentions* a key type; a commented-out or example directive
  can false-positive, and a binary keystore or a cert whose algorithm lives only in
  the DER will false-negative. It is a "look here" pointer, not proof. We never
  parse private-key material.
- **Dynamic / indirect use.** Crypto reached via `importlib`, plugins, or a wrapper
  library that re-exports a primitive under a different name.
- **Whether the algorithm is actually *used* for something sensitive.** An import is
  evidence, not proof of exposure; severity still needs human review.
- **Key sizes / parameters in most cases.** It flags the algorithm family, not every
  weak parameter choice.

## Honest framing

A clean scan means "no quantum-vulnerable public-key crypto was *imported in the
scanned Python source*." Production quantum-readiness also requires runtime,
transport, certificate, and dependency-level inventory — out of scope here. The
production migration itself (crypto-agility, dual-stack, key rotation) belongs in a
real crypto provider (e.g. AuthGate's), not in this discovery tool.
