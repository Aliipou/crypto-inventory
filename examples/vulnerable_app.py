"""A sample app using quantum-vulnerable cryptography (for the scanner to flag)."""

from cryptography.hazmat.primitives.asymmetric import rsa, ec  # HIGH, HNDL
from cryptography.hazmat.primitives.asymmetric import ed25519  # HIGH (signature)
from Crypto.PublicKey import RSA  # HIGH, HNDL (pycryptodome)
import rsa as rsa_lib  # HIGH, HNDL (standalone lib)


def make_keys():
    rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec.generate_private_key(ec.SECP256R1())
    ed25519.Ed25519PrivateKey.generate()
    RSA.generate(2048)
