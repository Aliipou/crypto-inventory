"""Static scanner: find quantum-vulnerable cryptography in Python source.

AST-based, stdlib-only. It inventories *imports* of public-key primitives that
Shor's algorithm breaks (and, advisory, Grover-weakened symmetric sizes), and
attaches the Harvest-Now-Decrypt-Later classification and the NIST PQC replacement.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from .rules import (
    CRYPTO_MODULE_HINTS,
    SHOR_BROKEN,
    SHOR_BROKEN_PYCRYPTO,
    STANDALONE_LIBS,
    Rule,
)


@dataclass(frozen=True)
class Finding:
    file: str
    lineno: int
    name: str
    rule: Rule


def _looks_like_crypto(module: str | None) -> bool:
    if not module:
        return False
    return any(h in module.lower() for h in CRYPTO_MODULE_HINTS)


def scan_file(path: Path) -> list[Finding]:
    try:
        tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError, OSError, ValueError):
        return []

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if not _looks_like_crypto(node.module):
                continue
            for alias in node.names:
                rule = SHOR_BROKEN.get(alias.name.lower()) or SHOR_BROKEN_PYCRYPTO.get(alias.name)
                if rule:
                    findings.append(Finding(str(path), node.lineno, alias.name, rule))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in STANDALONE_LIBS:
                    findings.append(Finding(str(path), node.lineno, top, STANDALONE_LIBS[top]))
                elif _looks_like_crypto(alias.name):
                    rule = SHOR_BROKEN.get(alias.name.split(".")[-1].lower())
                    if rule:
                        findings.append(Finding(str(path), node.lineno, alias.name.split(".")[-1], rule))
    return findings


def scan(paths) -> list[Finding]:
    # Lazy imports: avoid import cycles (these frontends import Finding from here).
    from .certs import is_cert_or_config, scan_cert_or_config
    from .manifests import is_manifest, scan_manifest
    from .rust_frontend import is_rust_source, scan_rust_file

    out: list[Finding] = []
    for root in paths:
        p = Path(root)
        if p.is_file():
            files = [p]
        else:
            files = sorted(
                set(p.rglob("*.py"))
                | {f for f in p.rglob("*") if f.is_file() and is_rust_source(f)}
                | {f for f in p.rglob("*") if f.is_file() and is_manifest(f)}
                | {f for f in p.rglob("*") if f.is_file() and is_cert_or_config(f)}
            )
        for f in files:
            if f.suffix == ".py":
                out.extend(scan_file(f))
            elif is_rust_source(f):
                out.extend(scan_rust_file(f))
            elif is_manifest(f):
                out.extend(scan_manifest(f))
            elif is_cert_or_config(f):
                out.extend(scan_cert_or_config(f))
    return out


def summarize(findings: list[Finding]) -> dict:
    high = [f for f in findings if f.rule.severity == "HIGH"]
    hndl = [f for f in findings if f.rule.hndl]
    return {
        "total": len(findings),
        "high": len(high),
        "hndl": len(hndl),  # harvest-now-decrypt-later: the urgent confidentiality risk
        "algorithms": sorted({f.rule.algo for f in findings}),
    }
