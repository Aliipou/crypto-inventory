"""Rust-source frontend: detect quantum-vulnerable crypto in `.rs` files.

The AST scanner is Python-only, so it cannot see crypto written in other languages
— including AuthGate's own Ed25519, which lives in Rust. This frontend closes that
named gap with a *regex* signal over Rust source: it matches `use` statements and
crate references (and a few unambiguous API entry points) for the common
Shor-broken crates, then maps each to the existing Rule/Finding model.

This is NOT a Rust parser. It is line/regex matching tuned for precision: it keys
off `use`/path syntax and known crate names rather than the bare word (so "rsa" in
a comment or string does not flag). It will miss crypto reached through re-exports,
macros, or aliases — same class of limitation the Python AST scanner has with
dynamic imports. Discovery only.
"""

from __future__ import annotations

import re
from pathlib import Path

from .rules import Rule
from .scan import Finding

_KEX = "ML-KEM (FIPS 203)"
_SIG = "ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)"

# Crate / module token (as it appears in a `use` path or fully-qualified call)
# -> rule. Keys are the lowercase Rust path segment, hyphens normalized to '_'
# (a crate named `ed25519-dalek` is referenced in code as `ed25519_dalek`).
VULN_CRATES: dict[str, Rule] = {
    "ed25519": Rule("Ed25519", "HIGH", False, "ed25519 signatures (ECDLP) are broken by Shor's algorithm", _SIG),
    "ed25519_dalek": Rule("Ed25519", "HIGH", False, "ed25519-dalek implements Ed25519 (ECDLP, Shor-broken)", _SIG),
    "x25519": Rule("X25519", "HIGH", True, "X25519 key agreement (ECDLP) is broken by Shor's algorithm", _KEX),
    "x25519_dalek": Rule("X25519", "HIGH", True, "x25519-dalek implements X25519 (ECDLP, Shor-broken)", _KEX),
    "rsa": Rule("RSA", "HIGH", True, "the `rsa` crate implements RSA (Shor factors the modulus)", f"{_KEX} / {_SIG}"),
    "ecdsa": Rule("ECDSA", "HIGH", False, "the `ecdsa` crate implements ECDSA (ECDLP, Shor-broken)", _SIG),
    "p256": Rule("Elliptic Curve", "HIGH", True, "the `p256` crate implements NIST P-256 ECDSA/ECDH (Shor-broken)", f"{_KEX} (KEX) / {_SIG} (sign)"),
    "p384": Rule("Elliptic Curve", "HIGH", True, "the `p384` crate implements NIST P-384 ECDSA/ECDH (Shor-broken)", f"{_KEX} (KEX) / {_SIG} (sign)"),
    "k256": Rule("Elliptic Curve", "HIGH", True, "the `k256` crate implements secp256k1 ECDSA/ECDH (Shor-broken)", f"{_KEX} (KEX) / {_SIG} (sign)"),
    "dsa": Rule("DSA", "HIGH", False, "the `dsa` crate implements DSA (discrete log, Shor-broken)", _SIG),
    "elliptic_curve": Rule("Elliptic Curve", "HIGH", True, "the `elliptic-curve` crate provides ECC primitives (ECDLP, Shor-broken)", f"{_KEX} (KEX) / {_SIG} (sign)"),
    # `ring` aggregates many primitives; only flag its asymmetric signature module.
    "ring_signature": Rule("RSA/ECDSA/Ed25519", "HIGH", True, "ring's `signature` module exposes RSA/ECDSA/Ed25519 (Shor-broken)", f"{_KEX} / {_SIG}"),
}

# A `use` path or fully-qualified path. Captures the leading `::`-separated
# segment chain so we can inspect the crate root and (for ring) the submodule.
#   use ed25519_dalek::SigningKey;
#   use rsa::{RsaPrivateKey, RsaPublicKey};
#   let _ = ring::signature::Ed25519KeyPair::generate(...);
_USE = re.compile(r"^\s*(?:pub\s+)?use\s+([A-Za-z_][A-Za-z0-9_]*(?:\s*::\s*[A-Za-z_][A-Za-z0-9_*{}]*)*)")
_PATH = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*::\s*([A-Za-z_][A-Za-z0-9_]*)")


def is_rust_source(path: Path) -> bool:
    return path.suffix == ".rs"


def _strip_comment(line: str) -> str:
    """Drop a trailing `//` line comment. Coarse: does not handle `//` inside a
    string literal, but Rust crate paths do not contain `//`, so a `use`/path
    match before the first `//` is what we want and string contents after it are
    discarded — exactly the precision we want."""
    return line.split("//", 1)[0]


def _rule_for_segment(root: str, second: str | None) -> tuple[str, Rule] | None:
    root = root.lower()
    if root == "ring":
        # Only the asymmetric signature module of ring is in scope.
        if second and second.lower() == "signature":
            return "ring::signature", VULN_CRATES["ring_signature"]
        return None
    rule = VULN_CRATES.get(root)
    if rule:
        return root, rule
    return None


def scan_rust_file(path: Path) -> list[Finding]:
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return []

    findings: list[Finding] = []
    in_block_comment = False
    for lineno, raw in enumerate(lines, 1):
        line = raw
        # Coarse `/* ... */` block-comment handling (whole-line granularity).
        if in_block_comment:
            if "*/" in line:
                line = line.split("*/", 1)[1]
                in_block_comment = False
            else:
                continue
        if "/*" in line:
            before, _, after = line.partition("/*")
            line = before
            if "*/" not in after:
                in_block_comment = True
        line = _strip_comment(line)
        if not line.strip():
            continue

        seen_roots: set[str] = set()  # one finding per crate per line

        m = _USE.match(line)
        if m:
            segments = [s.strip() for s in re.split(r"::", m.group(1))]
            root = segments[0]
            second = segments[1] if len(segments) > 1 else None
            hit = _rule_for_segment(root, second)
            if hit:
                name, rule = hit
                seen_roots.add(root.lower())
                findings.append(Finding(str(path), lineno, name, rule))

        # Fully-qualified call/path usage elsewhere on the line (e.g. inside fn
        # bodies) — `crate::Item` / `ring::signature::...`.
        for pm in _PATH.finditer(line):
            root, second = pm.group(1), pm.group(2)
            if root.lower() in seen_roots:
                continue
            hit = _rule_for_segment(root, second)
            if hit:
                name, rule = hit
                seen_roots.add(root.lower())
                findings.append(Finding(str(path), lineno, name, rule))

    return findings
