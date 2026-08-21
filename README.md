# crypto-inventory

**Live (graph):** [https://ali-crypto-inventory.vercel.app](https://ali-crypto-inventory.vercel.app)

A static scanner that **inventories quantum-vulnerable cryptography** in Python
source and scores **Harvest-Now-Decrypt-Later (HNDL)** risk — the first concrete
step of a post-quantum migration: *you can't migrate what you can't find.*

Stdlib only, zero dependencies, dev/CI tool. Independent of any other system.

## Why

Shor's algorithm breaks all deployed public-key crypto (RSA, ECC, Diffie-Hellman,
DSA/ECDSA/EdDSA). NIST has finalized PQC replacements (ML-KEM / ML-DSA / SLH-DSA),
and the migration has started. The urgent part is **HNDL**: data whose
confidentiality is protected today by RSA/ECC key-exchange can be *recorded now and
decrypted later* once a quantum computer exists — so confidentiality is already at
risk, years before such a computer is built.

## What it does

```bash
python -m crypto_inventory scan src/
```

For every import of a Shor-broken primitive it reports the file/line, the algorithm,
whether it is **HNDL-urgent** (confidentiality, retroactive) or a signature (urgent
but not retroactive), *why* it breaks, and the **NIST PQC replacement** to migrate to.
Exit code is non-zero when HIGH findings exist (`--fail-on high|any|none`), so it
drops into CI as a "no new quantum-vulnerable crypto" gate.

```
[HIGH] src/keys.py:3  rsa (RSA)  HNDL: harvest-now-decrypt-later
        Shor's algorithm factors the modulus
        -> migrate to ML-KEM (FIPS 203) for key exchange; ML-DSA (FIPS 204) for signatures
```

## Frontends (what it scans)

Beyond Python source it now has additional *frontends*, each a coarser signal that
the AST scanner cannot give, all flowing into the same Rule/Finding model and every
output format (text / CycloneDX CBOM / SARIF) and the `--policy` gate:

- **Python AST** — imports of Shor-broken primitives (the precise core).
- **Dependency manifests** — `requirements*.txt`, `pyproject.toml`, etc. naming a
  vulnerable package (`rsa`, `ecdsa`, `pynacl`, `pycryptodome`).
- **Rust source (`.rs`)** — regex/`use`-statement matching for the common
  quantum-vulnerable crates: `ed25519`/`ed25519-dalek`/`ed25519-compact`,
  `x25519-dalek`, `curve25519-dalek`, `rsa`, `ecdsa`, `p256`/`p384`/`k256`,
  `secp256k1`, `dsa`, `elliptic-curve`, `openssl` (RSA/EC/DSA submodules), and
  `ring`'s `signature`/`agreement` modules. Post-quantum crates (`pqcrypto`,
  `ml-kem`, `ml-dsa`, …) are the migration goal and are never flagged. Each
  finding carries a `confidence` (`high` for a direct crate path, `low` for a
  vulnerable crate imported under an `as` alias, whose downstream call sites are
  invisible to regex). This closes a real gap: the Python scanner could not see
  Rust crypto such as AuthGate's own Ed25519. It is *not* a Rust parser — it keys
  off crate/`use` paths, not bare words, so "rsa" in a comment or string is not
  flagged.
- **Certificates / TLS config** — a deliberately **coarse** transport signal:
  a `*.pem`/`*.crt`/`*.cer`/`*.key` file is flagged `MEDIUM` as "certificate or key
  present — verify the key algorithm" (we do not parse the DER, so the algorithm is
  unverified); a config file (`*.conf`/`*.cnf`/`openssl.cnf`/`*.yaml`/`*.yml`/`*.ini`/
  `*.toml`) that *names* an RSA/ECDSA/EC/DSA key type is flagged `HIGH` for that
  algorithm. Low-resolution by design — a "look here" pointer, not proof.

## Scope (deliberately narrow)

This is the **discovery / inventory** wedge — *not* a migration engine, key-rotation
system, or "crypto OS." It does one thing well: find the vulnerable crypto and tell
you what to replace it with. Where it sits in the ecosystem:

```
AuthGate        — who may do what          (capability)
boundary-guard  — is the architecture intact (dependency lint)
crypto-inventory— is the crypto quantum-ready (cryptography lifecycle)
```

All independent; none imports another.

## Run

```bash
python -m crypto_inventory scan examples/
python -m crypto_inventory scan examples/ --format cyclonedx   # CycloneDX CBOM (machine-readable, for audits/tooling)
python -m unittest discover -s tests -t .
```

It can emit a **CycloneDX 1.6 CBOM** (Cryptographic Bill of Materials) — the format
enterprises and regulators consume — with each finding as a `cryptographic-asset`
carrying its HNDL flag and PQC replacement. Pragmatic shape, not full-spec conformance.

See `THREAT_MODEL.md` for what it can and cannot detect.
