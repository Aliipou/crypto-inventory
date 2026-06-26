// A sample Rust module using quantum-vulnerable cryptography (for the scanner).
// The word "rsa" here in a comment must NOT be flagged on its own.

use ed25519_dalek::SigningKey; // HIGH (signature) — mirrors AuthGate's own Ed25519
use rsa::{RsaPrivateKey, RsaPublicKey}; // HIGH, HNDL
use x25519_dalek::EphemeralSecret; // HIGH, HNDL (key agreement)

fn sign_and_exchange() {
    let _key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let _pk = ring::signature::Ed25519KeyPair::generate(); // HIGH via ring::signature
    // a plain mention of ecdsa in a comment should not flag
    let _note = "this string mentions rsa but is not a use path";
}
