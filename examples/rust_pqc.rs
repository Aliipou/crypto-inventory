// A post-quantum Rust module: this is the MIGRATION GOAL, not a vulnerability.
// The scanner must NOT flag any of these — they are the PQC replacements.

use pqcrypto_mlkem::mlkem768::{keypair, encapsulate, decapsulate}; // ML-KEM (FIPS 203)
use pqcrypto_mldsa::mldsa65::{keypair as sig_keypair, sign, verify}; // ML-DSA (FIPS 204)
use ml_kem::MlKem768; // RustCrypto ML-KEM
use ml_dsa::MlDsa65;  // RustCrypto ML-DSA

fn main() {
    let (_pk, _sk) = keypair();
    let _k = ml_kem::MlKem768::default();
}
