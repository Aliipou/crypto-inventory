# crypto-inventory — industrial design dossier

> Produced against the `ohje.md` brief (Principal Architect / Security / Product / CTO).
> **Honesty rule:** engineering sections are real and testable. **Market sections
> (7–9, 22–24) are hypotheses, not facts** — they require customer interviews and
> competitor analysis before any are trusted. Labeled `⚠️ HYPOTHESIS` accordingly.
> The recommended product is not speculative: its **v1 already ships in this repo**.

## Candidate architectures considered, and why they died

| Candidate | Kill shot |
|---|---|
| Crypto **migration platform** (inventory+migrate+rotate+certs+compliance) | platform syndrome (brief forbids it); unsellable megaproduct; multi-year sales cycle |
| Crypto-**agility runtime** (swap algorithms live) | must live in the TLS/crypto stack → competes with OpenSSL/BoringSSL/cloud-KMS; overlaps AuthGate's provider → not independent |
| Quantum-**readiness dashboard** | a chart over data you don't own; value is the data, not the UI |
| Emergency crypto **recovery** | speculative trigger; nobody pays now for a maybe-2040 event |
| **Crypto discovery + CBOM + HNDL** ✅ | single responsibility, independent, regulator-mandated *now*, useful even if quantum never arrives |

**Recommended: crypto discovery / CBOM.** The rest of this dossier designs *that*.

---

1. **Mission** — Give any organization a continuously-trustworthy inventory of *where* it uses cryptography and *which of it dies to a quantum computer*. You cannot migrate what you cannot find.

2. **Elevator pitch** — A cryptographic bill of materials (CBOM) engine: point it at your code and it tells you every quantum-vulnerable algorithm, its Harvest-Now-Decrypt-Later risk, and what to replace it with — in a standard format.

3. **Single responsibility** — *Discovery and inventory of cryptographic assets.* Not migration, not key management, not a scanner suite.

4. **Core philosophy** — Static, evidence-based, honest about limits; one job done well; CBOM as a portable artifact, not a platform.

5. **Why it exists** — The first, mandatory step of every PQC migration is an inventory, and almost no one has one.

6. **Industrial problem** — Large orgs have decades of RSA/ECC across code, dependencies, certs, configs, and protocols, with no map. Regulators now demand the map.

7. **Current market gap** — ⚠️ HYPOTHESIS: most tooling jumps to "migration"/"agility" and assumes the inventory exists; the boring discovery layer is under-served. *Validate with buyers.*

8. **Existing competitors** — ⚠️ HYPOTHESIS, verify each: crypto-posture/discovery vendors (e.g. SandboxAQ/Cryptosense, IBM Quantum Safe), SBOM/CBOM tooling (CycloneDX ecosystem), SAST vendors adding crypto rules. *Names and positioning need confirmation.*

9. **Why current products fail** — ⚠️ HYPOTHESIS: heavy/proprietary, agent-based, priced for F500, or bundled into suites; weak on source-level CBOM as a portable artifact. *Validate.*

10. **Long-term moat** — Breadth × accuracy of the cryptographic rule corpus + ecosystem language coverage + being the trusted *open* CBOM producer regulators reference. Data/rules moat, not platform lock-in.

11. **Architecture** — A small deterministic core (AST/parse → match against a versioned crypto-rule corpus → findings) + pluggable *language/source frontends* + pluggable *output formats* (text, CycloneDX CBOM, SARIF). No runtime, no network, no agents.

12. **Repository structure** — `crypto_inventory/{rules,scan,cbom,cli}` + `tests/` + `examples/`. One repo, no monorepo, no platform.

13. **Core modules** — `rules` (knowledge base), `scan` (AST frontend), `cbom` (CycloneDX export), `cli`. (All present today.)

14. **Plugin model** — Frontends (Python now; later JS/Go/Java/configs/certs) and formatters (text/CBOM now; SARIF/PDF later) are additive plugins around an unchanged core. Rules are data, not code.

15. **Threat model** — See `THREAT_MODEL.md`. Adversary = stale/evasive code hiding crypto; goal = false confidence. False negatives are the cardinal sin.

16. **Failure model** — Worst case is a *clean* report that misses crypto (false negative) → false "PQC-ready." Mitigation: never claim completeness; surface unanalyzable files; honest scope in every report.

17. **Red-team plan** — Adversarial tests for dynamic/aliased imports, vendored/generated code, non-source crypto, rule gaps; pin each miss as a documented limitation (mirrors boundary-guard's red-team discipline).

18. **Security assumptions** — Read-only static analysis; trusts only the source on disk; no execution of scanned code; deterministic output.

19. **What MUST NOT be included** — No migration execution, no key/cert management, no runtime hooks, no agents, no "platform", no AI scoring on the trust path, no dependence on AuthGate/boundary-guard/authrobo. Stay a discovery tool.

20. **20-year roadmap** — ⚠️ directional: source CBOM → dependency/cert/config inventory → continuous CBOM in CI → the reference open CBOM producer. Revisit yearly.

21. **50-year vision** — ⚠️ scenario, not prediction: the standard way any system declares its cryptographic posture — a "nutrition label" for crypto. Re-decide every ~3 years against evidence.

22. **Commercialization** — ⚠️ HYPOTHESIS: open-source core + paid breadth (more languages, cert/runtime frontends, hosted continuous CBOM, compliance reports). *Unvalidated.*

23. **Enterprise licensing** — ⚠️ HYPOTHESIS: per-org subscription for the enterprise frontends + support/SLAs; core stays MIT. *Unvalidated.*

24. **Open-source strategy** — Core + Python frontend + CBOM exporter MIT and public, to become the trusted, auditable reference; monetize breadth and operations, never the core.

25. **Standards alignment** — Output **CycloneDX CBOM** (OWASP) and **SARIF** (CI annotations); track ISO/IEC SBOM work. (CBOM export shipped.)

26. **NIST PQC** — Map every finding to **FIPS 203 (ML-KEM) / 204 (ML-DSA) / 205 (SLH-DSA)**; track NIST NCCoE "Migration to PQC" and CNSA 2.0 timelines. *Verify current revisions before publishing.*

27. **EU regulations** — Relevant: **DORA** (financial resilience), **NIS2**, eIDAS, and the EU PQC coordinated roadmap. *Verify applicability/dates with counsel.*

28. **Migration strategy** — The tool stops at *discovery + recommendation*; actual migration (agility/dual-stack/rotation) belongs in a real crypto provider (e.g. AuthGate's), **not** here — preserving single responsibility.

29. **Version 1 (shipped)** — Python source scanner, HNDL classification, NIST PQC replacement, CycloneDX CBOM, CI gate. Validated on real third-party code (paramiko).

30. **Version 2** — More language frontends (JS/Go/Java) + SARIF output + dependency-manifest scanning.

31. **Version 3** — Certificate/TLS-config inventory, continuous CBOM in CI, diff/drift between scans.

32. **Ultimate version** — A continuously-maintained, standards-format cryptographic bill of materials across an organization's entire estate — the inventory layer the whole PQC transition is built on. Still just discovery.

---

## Self-attack (the brief's "try to kill it")

- *"Just another scanner."* → Mitigated by single-responsibility + CBOM-as-portable-artifact + being the open reference, not a suite.
- *Static-only is incomplete.* → True and **disclosed**; honesty is the product's integrity. v2/v3 add frontends; completeness is never claimed.
- *Market may not pay for discovery alone.* → The real risk. **Requires validation** (sections 7–9, 22–23) before investment. Do not trust this dossier's market claims until then.
- *Regulatory tailwind might be slower than hoped.* → Possible; the tool is still useful for ordinary audit/supply-chain today, satisfying "valuable even if quantum is delayed."
