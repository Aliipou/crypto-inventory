"""CLI: inventory quantum-vulnerable cryptography and score HNDL risk.

    python -m crypto_inventory scan <paths...> [--format text|cyclonedx] [--fail-on high|any|none]
"""

from __future__ import annotations

import argparse
import sys

from . import cbom
from .scan import scan, summarize

_MARK = {"HIGH": "[HIGH]", "MEDIUM": "[MED ]"}


def _exit_code(fail_on: str, findings) -> int:
    if fail_on == "none":
        return 0
    if fail_on == "any":
        return 1 if findings else 0
    return 1 if any(f.rule.severity == "HIGH" for f in findings) else 0  # default: HIGH


def cmd_scan(args) -> int:
    findings = scan(args.paths)

    if args.format == "cyclonedx":
        print(cbom.dumps(findings))
        return _exit_code(args.fail_on, findings)

    if not findings:
        print(f"OK — no quantum-vulnerable cryptography found under {', '.join(args.paths)}")
        return 0

    print(f"QUANTUM-VULNERABLE CRYPTOGRAPHY ({len(findings)} findings)\n")
    for f in sorted(findings, key=lambda x: (x.rule.severity != "HIGH", x.file, x.lineno)):
        hndl = "  HNDL: harvest-now-decrypt-later" if f.rule.hndl else ""
        print(f"  {_MARK[f.rule.severity]} {f.file}:{f.lineno}  {f.name} ({f.rule.algo}){hndl}")
        print(f"          {f.rule.why}")
        print(f"          -> migrate to {f.rule.replacement}\n")

    s = summarize(findings)
    print("-" * 60)
    print(f"  algorithms: {', '.join(s['algorithms'])}")
    print(f"  HIGH (Shor-broken): {s['high']}   HNDL-urgent (confidentiality): {s['hndl']}")
    return _exit_code(args.fail_on, findings)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="crypto-inventory")
    sub = p.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="scan paths for quantum-vulnerable crypto")
    sc.add_argument("paths", nargs="*", default=["."])
    sc.add_argument("--format", choices=["text", "cyclonedx"], default="text")
    sc.add_argument("--fail-on", choices=["high", "any", "none"], default="high")
    sc.set_defaults(func=cmd_scan)
    return p


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    args = build_parser().parse_args(argv)
    return args.func(args)
