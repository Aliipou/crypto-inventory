"""Rigorous tests for the crypto-policy gate ("which algorithms are allowed, when")."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from crypto_inventory import cli, scan_file
from crypto_inventory.policy import load_forbidden, violations

ROOT = Path(__file__).resolve().parents[1]
VULN = str(ROOT / "examples" / "vulnerable_app.py")   # RSA, Elliptic Curve, Ed25519
CLEAN = str(ROOT / "examples" / "pqc_ready_app.py")    # no public-key crypto


def _policy_file(obj):
    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(obj, f)
    f.close()
    return f.name


def _run(argv):
    out = io.StringIO()
    code = 0
    try:
        with redirect_stdout(out):
            code = cli.main(argv)
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
    return code, out.getvalue()


class TestPolicyUnit(unittest.TestCase):
    def test_load_forbidden(self):
        p = _policy_file({"forbidden": ["RSA", " ECDSA "]})
        self.assertEqual(load_forbidden(p), {"RSA", "ECDSA"})

    def test_load_missing_key_is_empty(self):
        p = _policy_file({})
        self.assertEqual(load_forbidden(p), set())

    def test_violations_filters_by_algo(self):
        findings = scan_file(Path(VULN))
        self.assertTrue(violations(findings, {"RSA"}))
        self.assertEqual(violations(findings, {"DSA"}), [])  # DSA not present


class TestPolicyCli(unittest.TestCase):
    def test_forbidding_present_algo_fails(self):
        p = _policy_file({"forbidden": ["RSA"]})
        code, out = _run(["scan", VULN, "--policy", p])
        self.assertEqual(code, 1)
        self.assertIn("FORBIDDEN algorithms present: RSA", out)

    def test_forbidding_absent_algo_passes_even_with_high_findings(self):
        # The repo HAS HIGH findings (RSA/EC), but the policy only forbids DSA (absent),
        # so the policy gate PASSES — policy overrides --fail-on.
        p = _policy_file({"forbidden": ["DSA"]})
        code, out = _run(["scan", VULN, "--policy", p])
        self.assertEqual(code, 0)
        self.assertIn("no forbidden algorithms present", out)

    def test_forbidding_ec_fails(self):
        p = _policy_file({"forbidden": ["Elliptic Curve"]})
        code, _ = _run(["scan", VULN, "--policy", p])
        self.assertEqual(code, 1)

    def test_clean_repo_passes_any_policy(self):
        p = _policy_file({"forbidden": ["RSA", "Elliptic Curve"]})
        code, _ = _run(["scan", CLEAN, "--policy", p])
        self.assertEqual(code, 0)

    def test_empty_forbidden_passes(self):
        p = _policy_file({"forbidden": []})
        code, _ = _run(["scan", VULN, "--policy", p])
        self.assertEqual(code, 0)

    def test_policy_works_with_machine_formats(self):
        p = _policy_file({"forbidden": ["RSA"]})
        for fmt in ("cyclonedx", "sarif"):
            with self.subTest(fmt=fmt):
                code, out = _run(["scan", VULN, "--format", fmt, "--policy", p])
                self.assertEqual(code, 1)              # policy still gates
                self.assertTrue(json.loads(out))       # output is still valid JSON


if __name__ == "__main__":
    unittest.main()
