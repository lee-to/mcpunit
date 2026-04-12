#![no_main]
//! Fuzz the JSON-RPC message parser used by both transports.
//!
//! The parser is tagged `#[serde(untagged)]` so malformed inputs should
//! surface as clean `Err(_)` values — panics here are bugs. Run with:
//!
//! ```bash
//! cargo +nightly fuzz run jsonrpc_parser -- -max_total_time=60
//! ```

use libfuzzer_sys::fuzz_target;
use mcpunit::transport::JsonRpcMessage;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<JsonRpcMessage>(data);
});
