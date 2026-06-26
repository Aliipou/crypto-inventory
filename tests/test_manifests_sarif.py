import json
import tempfile
import textwrap
import unittest
from pathlib import Path

from crypto_inventory import scan
from crypto_inventory.manifests import is_manifest, scan_manifest
from crypto_inventory.sarif import dumps as sarif_dumps, to_sarif
from crypto_inventory import scan_file

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


def _write(tmp, name, content):
    p = Path(tmp) / name
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


class TestManifests(unittest.TestCase):
    def test_detects_vulnerable_packages(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write(tmp, "requirements.txt", "rsa==4.9\necdsa>=0.18\npynacl==1.5.0\nrequests==2.31.0\n")
            names = {f.name for f in scan_manifest(p)}
            self.assertEqual(names, {"rsa", "ecdsa", "pynacl"})

    def test_ignores_safe_packages(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write(tmp, "requirements.txt", "requests==2.31.0\nnumpy\nflask\n")
            self.assertEqual(scan_manifest(p), [])

    def test_no_false_positive_on_substring_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write(tmp, "requirements.txt", "django-rsa-helper==1.0\n")
            self.assertEqual(scan_manifest(p), [])  # 'django-rsa-helper' != 'rsa'

    def test_is_manifest(self):
        self.assertTrue(is_manifest(Path("requirements.txt")))
        self.assertTrue(is_manifest(Path("requirements-dev.txt")))
        self.assertTrue(is_manifest(Path("pyproject.toml")))
        self.assertFalse(is_manifest(Path("module.py")))

    def test_scan_picks_up_manifests_and_py_together(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write(tmp, "requirements.txt", "rsa==4.9\n")
            _write(tmp, "app.py", "from cryptography.hazmat.primitives.asymmetric import ec\n")
            algos = {f.rule.algo for f in scan([tmp])}
            self.assertIn("RSA", algos)            # from manifest
            self.assertIn("Elliptic Curve", algos)  # from source


class TestSarif(unittest.TestCase):
    def test_sarif_shape(self):
        findings = scan_file(EXAMPLES / "vulnerable_app.py")
        s = to_sarif(findings)
        self.assertEqual(s["version"], "2.1.0")
        self.assertEqual(s["runs"][0]["tool"]["driver"]["name"], "crypto-inventory")
        self.assertTrue(s["runs"][0]["results"])
        r0 = s["runs"][0]["results"][0]
        self.assertIn(r0["level"], ("error", "warning"))
        self.assertIn("startLine", r0["locations"][0]["physicalLocation"]["region"])

    def test_sarif_is_valid_json(self):
        s = sarif_dumps(scan_file(EXAMPLES / "vulnerable_app.py"))
        self.assertEqual(json.loads(s)["version"], "2.1.0")


if __name__ == "__main__":
    unittest.main()
