import tempfile
import textwrap
import unittest
from pathlib import Path

from crypto_inventory import scan, scan_file, summarize

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


def _scan_src(src: str):
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "m.py"
        p.write_text(textwrap.dedent(src), encoding="utf-8")
        return scan_file(p)


class TestScan(unittest.TestCase):
    def test_flags_rsa_and_ec_from_cryptography(self):
        f = _scan_src("from cryptography.hazmat.primitives.asymmetric import rsa, ec\n")
        algos = {x.rule.algo for x in f}
        self.assertIn("RSA", algos)
        self.assertIn("Elliptic Curve", algos)

    def test_flags_pycryptodome_rsa(self):
        f = _scan_src("from Crypto.PublicKey import RSA\n")
        self.assertEqual(f[0].rule.algo, "RSA")

    def test_flags_standalone_rsa_lib(self):
        f = _scan_src("import rsa\n")
        self.assertEqual(f[0].rule.algo, "RSA")

    def test_rsa_is_hndl_but_ecdsa_is_not(self):
        rsa_f = _scan_src("from cryptography.hazmat.primitives.asymmetric import rsa\n")[0]
        ecdsa_f = _scan_src("from cryptography.hazmat.primitives.asymmetric import ecdsa\n")[0]
        self.assertTrue(rsa_f.rule.hndl)       # confidentiality -> harvest-now-decrypt-later
        self.assertFalse(ecdsa_f.rule.hndl)    # signatures -> not retroactive

    def test_no_false_positive_on_unrelated_ec_variable(self):
        # 'ec' as a local name, not imported from a crypto module
        f = _scan_src("ec = 5\nimport os\n")
        self.assertEqual(f, [])

    def test_pqc_ready_example_is_clean(self):
        self.assertEqual(scan_file(EXAMPLES / "pqc_ready_app.py"), [])

    def test_vulnerable_example_has_high_and_hndl(self):
        f = scan([str(EXAMPLES / "vulnerable_app.py")])
        s = summarize(f)
        self.assertGreaterEqual(s["high"], 3)
        self.assertGreaterEqual(s["hndl"], 2)

    def test_replacement_named(self):
        f = _scan_src("from cryptography.hazmat.primitives.asymmetric import rsa\n")[0]
        self.assertIn("ML-KEM", f.rule.replacement)


if __name__ == "__main__":
    unittest.main()
