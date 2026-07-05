import json
import tempfile
import textwrap
import unittest
from pathlib import Path

from crypto_inventory import scan_file, to_cyclonedx
from crypto_inventory.cbom import dumps


def _findings(src):
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "m.py"
        p.write_text(textwrap.dedent(src), encoding="utf-8")
        return scan_file(p)


class TestCBOM(unittest.TestCase):
    def test_shape_is_cyclonedx(self):
        bom = to_cyclonedx(_findings("from cryptography.hazmat.primitives.asymmetric import rsa\n"))
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        self.assertEqual(bom["specVersion"], "1.6")
        self.assertEqual(bom["components"][0]["type"], "cryptographic-asset")
        self.assertEqual(bom["components"][0]["name"], "RSA")

    def test_carries_hndl_and_replacement_properties(self):
        bom = to_cyclonedx(_findings("from cryptography.hazmat.primitives.asymmetric import rsa\n"))
        props = {p["name"]: p["value"] for p in bom["components"][0]["properties"]}
        self.assertEqual(props["crypto-inventory:hndl"], "true")
        self.assertIn("ML-KEM", props["crypto-inventory:replacement"])

    def test_dumps_is_valid_json(self):
        out = dumps(_findings("import rsa\n"))
        parsed = json.loads(out)
        self.assertEqual(parsed["components"][0]["name"], "RSA")

    def test_empty_findings_empty_components(self):
        bom = to_cyclonedx([])
        self.assertEqual(bom["components"], [])

    def test_carries_confidence_property(self):
        bom = to_cyclonedx(_findings("from cryptography.hazmat.primitives.asymmetric import rsa\n"))
        props = {p["name"]: p["value"] for p in bom["components"][0]["properties"]}
        self.assertIn(props["crypto-inventory:confidence"], ("high", "low"))


if __name__ == "__main__":
    unittest.main()
