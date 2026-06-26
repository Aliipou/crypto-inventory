"""Dependency-manifest frontend: detect quantum-vulnerable crypto *libraries*.

A project that depends on rsa / ecdsa / pynacl / pycryptodome almost certainly uses
Shor-broken public-key crypto even when no import is visible in the scanned source.
This complements the AST scanner with a dependency-level signal.
"""

from __future__ import annotations

import re
from pathlib import Path

from .rules import Rule
from .scan import Finding

_KEX = "ML-KEM (FIPS 203)"
_SIG = "ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)"

# normalized package name -> rule
VULN_PACKAGES: dict[str, Rule] = {
    "rsa": Rule("RSA", "HIGH", True, "the 'rsa' package implements RSA (Shor-broken)", f"{_KEX} / {_SIG}"),
    "ecdsa": Rule("ECDSA", "HIGH", False, "the 'ecdsa' package implements ECDSA (Shor-broken)", _SIG),
    "pynacl": Rule("Curve25519/Ed25519", "HIGH", True, "PyNaCl provides X25519/Ed25519 (ECC, Shor-broken)", f"{_KEX} / {_SIG}"),
    "pycryptodome": Rule("RSA/ECC/DSA", "HIGH", True, "pycryptodome provides RSA/ECC/DSA public-key crypto", f"{_KEX} / {_SIG}"),
    "pycryptodomex": Rule("RSA/ECC/DSA", "HIGH", True, "pycryptodomex provides RSA/ECC/DSA public-key crypto", f"{_KEX} / {_SIG}"),
    "pycrypto": Rule("RSA/ECC/DSA", "HIGH", True, "pycrypto provides RSA/ECC/DSA public-key crypto", f"{_KEX} / {_SIG}"),
}

_MANIFEST_NAMES = {"pyproject.toml", "setup.py", "setup.cfg", "Pipfile"}
_TOKEN = re.compile(r"[A-Za-z0-9_.-]+")


def _normalize(name: str) -> str:
    return name.strip().lower().replace("_", "-").split("[")[0]


def is_manifest(path: Path) -> bool:
    n = path.name
    return n in _MANIFEST_NAMES or (n.startswith("requirements") and path.suffix == ".txt")


def scan_manifest(path: Path) -> list[Finding]:
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return []
    findings: list[Finding] = []
    for lineno, raw in enumerate(lines, 1):
        line = raw.split("#", 1)[0]
        for token in _TOKEN.findall(line):
            rule = VULN_PACKAGES.get(_normalize(token))
            if rule:
                findings.append(Finding(str(path), lineno, _normalize(token), rule))
                break  # one finding per line
    return findings
