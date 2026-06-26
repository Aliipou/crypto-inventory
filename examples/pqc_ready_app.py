"""A sample app with no quantum-vulnerable public-key crypto (scanner stays quiet).

Uses only symmetric AES-256 and a hash — Grover-weakened at worst, not Shor-broken.
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes


def encrypt(key32: bytes, iv: bytes, data: bytes) -> bytes:
    c = Cipher(algorithms.AES256(key32), modes.GCM(iv))
    e = c.encryptor()
    return e.update(data) + e.finalize()


def digest(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA384())
    h.update(data)
    return h.finalize()
