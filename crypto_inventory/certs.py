"""Certificate / TLS-config frontend: a *coarse* transport-layer signal.

The AST and Rust scanners see crypto in source. A lot of quantum-vulnerable crypto
lives instead in deployed material: certificate/key files and TLS/OpenSSL config.
This frontend gives a deliberately low-resolution signal for that surface:

  * A `*.pem` / `*.crt` / `*.cer` / `*.key` file is flagged as "certificate or key
    present — verify the key algorithm" (MEDIUM, not HIGH). Its mere presence does
    NOT prove RSA/ECC: it could already be a PQC or symmetric artifact. We do not
    parse the DER/ASN.1, so we cannot tell — hence MEDIUM and an explicit
    "verify" instruction.
  * A config file (`*.conf` / `*.cnf` / `openssl.cnf` / `*.yaml` / `*.yml` / `*.ini`
    / `*.toml`) that *mentions* an RSA/ECDSA/EC key type or `default_bits`/curve
    directive is flagged HIGH for that specific algorithm — there the text names
    the primitive, so the signal is stronger.

This is honest about being coarse: it produces a "look here" pointer, not proof.
False positives (an example cert, a commented-out directive) and false negatives
(a binary keystore, a cert whose algorithm is only in the DER) are both expected.
Discovery only — it never reads private-key material for secrets, only filenames
and config text.
"""

from __future__ import annotations

import re
from pathlib import Path

from .rules import Rule
from .scan import Finding

_KEX = "ML-KEM (FIPS 203)"
_SIG = "ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)"

_CERT_SUFFIXES = {".pem", ".crt", ".cer", ".key", ".der"}
_CONFIG_SUFFIXES = {".conf", ".cnf", ".cfg", ".ini", ".yaml", ".yml", ".toml"}

# Certificate/key file present — algorithm unknown without parsing the bytes.
_CERT_RULE = Rule(
    "Certificate/Key (unverified)", "MEDIUM", True,
    "certificate or key file present — verify the key algorithm; if RSA/ECC it is Shor-broken",
    f"{_KEX} / {_SIG}",
)

# Config text that *names* a primitive. Each pattern -> rule. Patterns are matched
# against config-file lines (comments stripped) so a quantum-vulnerable key type
# declared in OpenSSL / web-server / app config is surfaced with its algorithm.
_CONFIG_PATTERNS: list[tuple[re.Pattern[str], Rule]] = [
    (re.compile(r"\brsa\b", re.IGNORECASE),
     Rule("RSA", "HIGH", True, "config declares an RSA key/algorithm (Shor factors the modulus)", f"{_KEX} / {_SIG}")),
    (re.compile(r"\becdsa\b", re.IGNORECASE),
     Rule("ECDSA", "HIGH", False, "config declares an ECDSA key/algorithm (ECDLP, Shor-broken)", _SIG)),
    (re.compile(r"\bec(?:dsa|dh)?param|prime256v1|secp\d|nistp\d", re.IGNORECASE),
     Rule("Elliptic Curve", "HIGH", True, "config declares an EC curve (ECDLP, Shor-broken)", f"{_KEX} (KEX) / {_SIG} (sign)")),
    (re.compile(r"\bdsa\b", re.IGNORECASE),
     Rule("DSA", "HIGH", False, "config declares a DSA key/algorithm (discrete log, Shor-broken)", _SIG)),
]


def is_cert_or_config(path: Path) -> bool:
    s = path.suffix.lower()
    return s in _CERT_SUFFIXES or s in _CONFIG_SUFFIXES


def _strip_config_comment(line: str) -> str:
    # OpenSSL/INI use '#'; YAML/TOML use '#' too. Coarse but adequate.
    return line.split("#", 1)[0]


def scan_cert_or_config(path: Path) -> list[Finding]:
    s = path.suffix.lower()
    if s in _CERT_SUFFIXES:
        # Filename-level signal only; we do not parse key material.
        return [Finding(str(path), 1, path.name, _CERT_RULE)]

    if s not in _CONFIG_SUFFIXES:
        return []

    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return []

    findings: list[Finding] = []
    seen_algos: set[str] = set()  # de-dupe per file: one finding per algorithm
    for lineno, raw in enumerate(lines, 1):
        line = _strip_config_comment(raw)
        if not line.strip():
            continue
        for pat, rule in _CONFIG_PATTERNS:
            if rule.algo in seen_algos:
                continue
            if pat.search(line):
                seen_algos.add(rule.algo)
                findings.append(Finding(str(path), lineno, rule.algo.lower(), rule))
    return findings
