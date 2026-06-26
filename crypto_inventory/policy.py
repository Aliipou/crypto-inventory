"""Organizational crypto policy — "which algorithms are allowed, when".

The tool owns no secrets; it only *decides*, per a declared policy, whether the
cryptography found is acceptable. "If RSA remains anywhere: FAIL." This is the
crypto-agility control: today you might forbid nothing extra (just flag the
quantum-vulnerable), tomorrow forbid RSA, then the next deprecated algorithm —
without changing code, only the policy file.

Policy file (JSON):

    { "forbidden": ["RSA", "ECDSA", "Diffie-Hellman"] }
"""

from __future__ import annotations

import json
from pathlib import Path


def load_forbidden(path) -> set[str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {str(a).strip() for a in data.get("forbidden", [])}


def violations(findings, forbidden: set[str]):
    return [f for f in findings if f.rule.algo in forbidden]
