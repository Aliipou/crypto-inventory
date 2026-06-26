import tempfile
import textwrap
import unittest
from pathlib import Path

from crypto_inventory import scan
from crypto_inventory.rust_frontend import is_rust_source, scan_rust_file
from crypto_inventory.certs import is_cert_or_config, scan_cert_or_config

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


def _write(tmp, name, content):
    p = Path(tmp) / name
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


class TestRustFrontend(unittest.TestCase):
    def test_detects_ed25519_and_rsa(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write(tmp, "lib.rs", """
                use ed25519_dalek::SigningKey;
                use rsa::RsaPrivateKey;
            """)
            algos = {f.rule.algo for f in scan_rust_file(p)}
            self.assertIn("Ed25519", algos)
            self.assertIn("RSA", algos)

    def test_rsa_is_hndl_ed25519_is_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write(tmp, "lib.rs", """
                use rsa::RsaPrivateKey;
                use ed25519_dalek::SigningKey;
            """)
            by_algo = {f.rule.algo: f for f in scan_rust_file(p)}
            self.assertTrue(by_algo["RSA"].rule.hndl)        # confidentiality
            self.assertFalse(by_algo["Ed25519"].rule.hndl)   # signature

    def test_detects_ring_signature_module_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write(tmp, "lib.rs", """
                use ring::signature::Ed25519KeyPair;
                use ring::digest::SHA256;
            """)
            findings = scan_rust_file(p)
            self.assertEqual(len(findings), 1)             # digest must NOT flag
            self.assertEqual(findings[0].rule.algo, "RSA/ECDSA/Ed25519")

    def test_no_false_positive_on_comments_and_strings(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write(tmp, "lib.rs", """
                // this comment mentions rsa, ecdsa and ed25519
                fn main() {
                    let _ = "rsa and ecdsa appear only in this string";
                    /* block comment: rsa ecdsa p256 */
                }
            """)
            self.assertEqual(scan_rust_file(p), [])

    def test_clean_example_is_clean(self):
        self.assertEqual(scan_rust_file(EXAMPLES / "rust_clean.rs"), [])

    def test_vulnerable_example_flags_multiple(self):
        algos = {f.rule.algo for f in scan_rust_file(EXAMPLES / "rust_vulnerable.rs")}
        self.assertIn("Ed25519", algos)
        self.assertIn("RSA", algos)
        self.assertIn("X25519", algos)

    def test_is_rust_source(self):
        self.assertTrue(is_rust_source(Path("a.rs")))
        self.assertFalse(is_rust_source(Path("a.py")))


class TestCertFrontend(unittest.TestCase):
    def test_cert_file_present_is_flagged_medium(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write(tmp, "server.crt", "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n")
            findings = scan_cert_or_config(p)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].rule.severity, "MEDIUM")
            self.assertIn("verify", findings[0].rule.why.lower())

    def test_key_suffix_flagged_without_reading_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write(tmp, "id.key", "anything")
            findings = scan_cert_or_config(p)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].lineno, 1)  # filename-level signal

    def test_config_naming_rsa_is_high(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write(tmp, "openssl.cnf", """
                [ req ]
                default_bits = 2048
                default_keytype = rsa
            """)
            algos = {f.rule.algo for f in scan_cert_or_config(p)}
            self.assertIn("RSA", algos)

    def test_config_naming_ec_curve(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write(tmp, "tls.conf", "curve = prime256v1\n")
            algos = {f.rule.algo for f in scan_cert_or_config(p)}
            self.assertIn("Elliptic Curve", algos)

    def test_config_dedupes_per_algorithm(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write(tmp, "x.cnf", "rsa\nrsa\nrsa\n")
            findings = [f for f in scan_cert_or_config(p) if f.rule.algo == "RSA"]
            self.assertEqual(len(findings), 1)

    def test_config_comment_only_mention_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write(tmp, "x.conf", "# rsa key here\nfoo = bar\n")
            self.assertEqual(scan_cert_or_config(p), [])

    def test_is_cert_or_config(self):
        self.assertTrue(is_cert_or_config(Path("a.pem")))
        self.assertTrue(is_cert_or_config(Path("a.cnf")))
        self.assertTrue(is_cert_or_config(Path("a.yaml")))
        self.assertFalse(is_cert_or_config(Path("a.py")))


class TestMixedDirIntegration(unittest.TestCase):
    def test_scan_picks_up_python_rust_and_manifest_together(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write(tmp, "app.py", "from cryptography.hazmat.primitives.asymmetric import ec\n")
            _write(tmp, "auth.rs", "use ed25519_dalek::SigningKey;\nuse rsa::RsaPrivateKey;\n")
            _write(tmp, "requirements.txt", "ecdsa>=0.18\n")
            _write(tmp, "openssl.cnf", "# rsa\nkey = rsa\n")
            algos = {f.rule.algo for f in scan([tmp])}
            self.assertIn("Elliptic Curve", algos)  # Python source
            self.assertIn("Ed25519", algos)         # Rust source
            self.assertIn("RSA", algos)             # Rust + config
            self.assertIn("ECDSA", algos)           # manifest


if __name__ == "__main__":
    unittest.main()
