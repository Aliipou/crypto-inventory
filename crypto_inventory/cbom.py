"""CycloneDX-shaped CBOM export (Cryptographic Bill of Materials).

Emits each finding as a CycloneDX 1.6 `cryptographic-asset` component — the format
crypto-asset inventory tooling, audits, and regulators consume. Pragmatic, not a
claim of full-spec conformance: enough structure to be machine-ingestible and honest.
"""

from __future__ import annotations

import json

from .scan import Finding

# Crude algorithm -> CycloneDX cryptographic primitive.
_PRIMITIVE = {
    "RSA": "pke",
    "ElGamal": "pke",
    "Elliptic Curve": "pke",
    "Diffie-Hellman": "key-agree",
    "ECDH": "key-agree",
    "X25519": "key-agree",
    "X448": "key-agree",
    "DSA": "signature",
    "ECDSA": "signature",
    "Ed25519": "signature",
    "Ed448": "signature",
    "AES-128": "block-cipher",
    "RSA/ECDSA/Ed25519": "signature",       # ring's aggregate signature module
    "Certificate/Key (unverified)": "unknown",  # coarse file-presence signal
}


def to_cyclonedx(findings: list[Finding], tool_version: str = "0.1.0") -> dict:
    components = []
    for i, f in enumerate(findings):
        components.append({
            "type": "cryptographic-asset",
            "name": f.rule.algo,
            "bom-ref": f"crypto-asset-{i}",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": _PRIMITIVE.get(f.rule.algo, "unknown"),
                    "executionEnvironment": "software-plain-ram",
                },
            },
            "properties": [
                {"name": "crypto-inventory:quantum-vulnerable", "value": "true"},
                {"name": "crypto-inventory:severity", "value": f.rule.severity},
                {"name": "crypto-inventory:hndl", "value": str(f.rule.hndl).lower()},
                {"name": "crypto-inventory:reason", "value": f.rule.why},
                {"name": "crypto-inventory:replacement", "value": f.rule.replacement},
            ],
            "evidence": {"occurrences": [{"location": f"{f.file}:{f.lineno}"}]},
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "tools": {
                "components": [
                    {"type": "application", "name": "crypto-inventory", "version": tool_version}
                ]
            }
        },
        "components": components,
    }


def dumps(findings: list[Finding], tool_version: str = "0.1.0") -> str:
    return json.dumps(to_cyclonedx(findings, tool_version), indent=2)
