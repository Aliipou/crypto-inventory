// A clean Rust module: no quantum-vulnerable public-key crypto.
// Mentions of "rsa", "ecdsa", and "ed25519" appear only in comments and strings
// below to confirm the scanner does not false-positive on bare words.

use std::collections::HashMap;
use sha2::Sha256; // hashing only — Grover-resistant at 256-bit, not in scope

fn main() {
    // We deliberately do NOT use rsa or ecdsa here.
    let label = "ed25519 is mentioned only as a string literal";
    let mut m: HashMap<String, u32> = HashMap::new();
    m.insert(label.to_string(), 1);
}
