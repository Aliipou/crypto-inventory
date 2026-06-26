# crypto-inventory — what it can and cannot detect (honest)

It is a **static, Python-source, import-level** scanner. It is a discovery aid, not
a proof of quantum-readiness. Do not claim "PQC-ready" from a clean scan alone.

## Detects

- Imports of Shor-broken public-key primitives (RSA, DH, DSA, EC/ECDSA/ECDH,
  Ed25519/Ed448, X25519/X448, ElGamal) from `cryptography`, `pycryptodome`/`Crypto`,
  and the standalone `rsa` / `ecdsa` libraries.
- HNDL classification (confidentiality/key-exchange vs. signatures) and the NIST PQC
  replacement.
- Advisory: Grover-weakened symmetric sizes (e.g. AES-128).

## Does NOT detect (known limitations)

- **Non-Python and non-source crypto.** TLS/SSH negotiated at runtime, certificates,
  HSM/KMS-managed keys, OpenSSL config, JWT alg fields, compiled/vendored binaries,
  other languages. Real inventory needs network + certificate + config scanners too.
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
