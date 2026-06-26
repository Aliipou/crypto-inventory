"""Knowledge base: which cryptographic primitives a large quantum computer breaks.

Shor's algorithm breaks all widely-deployed *public-key* crypto (RSA, finite-field
and elliptic-curve Diffie-Hellman, DSA/ECDSA/EdDSA). Grover's algorithm only halves
symmetric strength (AES-128 -> ~64-bit), so AES-256 and SHA-384+ stay safe.

HNDL = "Harvest Now, Decrypt Later": traffic/key-exchange protected today by a
Shor-broken primitive can be recorded now and decrypted once a quantum computer
exists. Confidentiality is retroactively at risk; signatures are not (you cannot
forge a past signature retroactively), so signatures are urgent but not HNDL.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    algo: str
    severity: str       # HIGH (Shor-broken) | MEDIUM (Grover-weakened)
    hndl: bool          # confidentiality at retroactive risk
    why: str
    replacement: str    # NIST PQC standard


_KEX = "ML-KEM (FIPS 203)"
_SIG = "ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)"

# Leaf import names (from a crypto module) -> rule. Lowercased for matching.
SHOR_BROKEN: dict[str, Rule] = {
    "rsa": Rule("RSA", "HIGH", True, "Shor's algorithm factors the modulus", f"{_KEX} for key exchange; {_SIG} for signatures"),
    "dsa": Rule("DSA", "HIGH", False, "Shor's algorithm solves the discrete log", _SIG),
    "dh": Rule("Diffie-Hellman", "HIGH", True, "Shor's algorithm solves the discrete log", _KEX),
    "ec": Rule("Elliptic Curve", "HIGH", True, "Shor's algorithm solves the ECDLP", f"{_KEX} (KEX) / {_SIG} (sign)"),
    "ecdsa": Rule("ECDSA", "HIGH", False, "Shor's algorithm solves the ECDLP", _SIG),
    "ecdh": Rule("ECDH", "HIGH", True, "Shor's algorithm solves the ECDLP", _KEX),
    "ed25519": Rule("Ed25519", "HIGH", False, "Shor's algorithm solves the ECDLP", _SIG),
    "ed448": Rule("Ed448", "HIGH", False, "Shor's algorithm solves the ECDLP", _SIG),
    "x25519": Rule("X25519", "HIGH", True, "Shor's algorithm solves the ECDLP", _KEX),
    "x448": Rule("X448", "HIGH", True, "Shor's algorithm solves the ECDLP", _KEX),
    "elgamal": Rule("ElGamal", "HIGH", True, "Shor's algorithm solves the discrete log", _KEX),
}

# pycryptodome / PyCrypto capitalised public-key module names.
SHOR_BROKEN_PYCRYPTO: dict[str, Rule] = {
    "RSA": SHOR_BROKEN["rsa"],
    "DSA": SHOR_BROKEN["dsa"],
    "ECC": SHOR_BROKEN["ec"],
    "ElGamal": SHOR_BROKEN["elgamal"],
}

# Grover-weakened (not broken) — advisory.
GROVER_WEAK: dict[str, Rule] = {
    "aes128": Rule("AES-128", "MEDIUM", False, "Grover's algorithm halves the key search to ~64-bit", "AES-256"),
}

# Standalone PyPI libraries whose top-level import already implies vulnerable use.
STANDALONE_LIBS: dict[str, Rule] = {
    "rsa": SHOR_BROKEN["rsa"],
    "ecdsa": SHOR_BROKEN["ecdsa"],
}

# A module path must look like crypto for leaf-name matching (cuts false positives).
CRYPTO_MODULE_HINTS = ("cryptography", "crypto", "cryptodome", "nacl", "rsa", "ecdsa", "openssl")
