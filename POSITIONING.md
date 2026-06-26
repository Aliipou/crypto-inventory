# Positioning — crypto-inventory as a Cryptographic-Trust gate

Designed around **cryptographic trust**, not "quantum". Quantum is the *trigger*,
not the identity — so the tool stays valuable even if large quantum computers arrive
late or the next big crypto transition comes from an algorithm break or a new standard.

## Single responsibility

**Decide whether the cryptography in a codebase is acceptable** — discover it, flag
the quantum-vulnerable, and enforce a declarable policy of which algorithms are
forbidden. Discovery + decision. Nothing else.

## Golden rule: owns no secrets

Like AuthGate "depends on nothing", this tool **owns no secrets**:

- no private keys, no certificates, no wallets, no key store, no HSM
- no financial state, no database
- pure read-only static analysis + a policy decision

## What it does NOT do (by design)

- ❌ implement cryptography
- ❌ execute migration / rotate keys / replace certs (that *owns secrets* → out)
- ❌ be a PKI, KMS, HSM, VPN, wallet, or blockchain
- ❌ become a 6-module "platform" (platform syndrome)

Migration *execution* belongs in a real crypto provider (e.g. AuthGate's PQC
provider). This tool stops at **discover → decide**.

## Place in the ecosystem (all independent, none inside another)

| Project | Responsibility |
|---|---|
| AuthGate | authorization (who may do what) |
| boundary-guard | architecture integrity (dependency boundaries) |
| **crypto-inventory** | **cryptographic trust (which crypto is allowed, when)** |

## The crypto-agility control

`--policy policy.json` declares the forbidden set. Your migration phase is one file:
today forbid nothing extra (just flag quantum-vulnerable); tomorrow `forbid: ["RSA"]`;
then the next deprecated algorithm — **without changing code**. "If RSA remains
anywhere: FAIL."
