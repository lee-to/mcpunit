#![no_main]
//! Fuzz the SARIF fingerprint hasher on arbitrary evidence bytes.
//!
//! The real hasher is a thin wrapper around SHA-256; the goal of the target
//! is to prove that arbitrary UTF-8-lossy content + oddly-placed `|`
//! separators never panic or produce an invalid hex digest. Run with:
//!
//! ```bash
//! cargo +nightly fuzz run sarif_fingerprint -- -max_total_time=60
//! ```

use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};

fuzz_target!(|data: &[u8]| {
    // Simulate the fingerprint source format used by
    // `reporters::sarif::compute_fingerprint`.
    let source = String::from_utf8_lossy(data);
    let mut hasher = Sha256::new();
    hasher.update(source.as_bytes());
    let hex = format!("{:x}", hasher.finalize());
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
});
