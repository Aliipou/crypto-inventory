"""crypto-inventory — static scanner for quantum-vulnerable cryptography.

Finds public-key crypto that Shor's algorithm breaks (RSA / ECC / DH / DSA) in
Python source, classifies Harvest-Now-Decrypt-Later risk, and names the NIST PQC
replacement. Dev/CI tool; independent of any other system. Stdlib only.
"""

from .rules import Rule
from .scan import Finding, scan, scan_file, summarize

__version__ = "0.1.0"

__all__ = ["Rule", "Finding", "scan", "scan_file", "summarize", "__version__"]
