"""SARIF 2.1.0 output — for GitHub code scanning / CI annotations.

Each finding becomes a SARIF result anchored to file:line, severity mapped to
error (HIGH / Shor-broken) or warning (MEDIUM / Grover-weakened).
"""

from __future__ import annotations

import json
from pathlib import PurePath

from .scan import Finding

_LEVEL = {"HIGH": "error", "MEDIUM": "warning"}


def to_sarif(findings: list[Finding], tool_version: str = "0.1.0") -> dict:
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rule_id = ("quantum-vulnerable/" + f.rule.algo).replace(" ", "-")
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": f.rule.algo,
            "shortDescription": {"text": f"{f.rule.algo} is broken by a large quantum computer"},
            "fullDescription": {"text": f.rule.why},
            "defaultConfiguration": {"level": _LEVEL.get(f.rule.severity, "warning")},
            "helpUri": "https://csrc.nist.gov/projects/post-quantum-cryptography",
        })
        msg = f"{f.name} ({f.rule.algo}) — {f.rule.why}. Migrate to {f.rule.replacement}."
        if f.rule.hndl:
            msg += " [HNDL: harvest-now-decrypt-later]"
        results.append({
            "ruleId": rule_id,
            "level": _LEVEL.get(f.rule.severity, "warning"),
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": PurePath(f.file).as_posix()},
                    "region": {"startLine": max(1, f.lineno)},
                }
            }],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "crypto-inventory",
                "version": tool_version,
                "informationUri": "https://github.com/Aliipou/crypto-inventory",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def dumps(findings: list[Finding], tool_version: str = "0.1.0") -> str:
    return json.dumps(to_sarif(findings, tool_version), indent=2)
