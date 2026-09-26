// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Fuzz the bytecode trust boundary: decode arbitrary bytes into a
//! [`loom_compiler::bytecode::Module`], then verify it. Properties: `decode`
//! never panics on any input; if it produces a `Module`, `verify` never
//! panics either, and re-encoding + re-decoding a `decode`d module is stable
//! (decode is a pure function of its bytes).

#![no_main]

use libfuzzer_sys::fuzz_target;
use loom_compiler::bytecode;
use loom_compiler::verify;

fuzz_target!(|data: &[u8]| {
    let Ok(module) = bytecode::decode(data) else {
        return;
    };
    let _ = verify::verify(&module);

    // decode -> encode -> decode should reach a fixed point: encoding a
    // successfully decoded module and decoding that again must succeed and
    // produce the same verifier verdict (defends `verify` against being
    // sensitive to how a `Module` arrived, not just its shape).
    let re_encoded = bytecode::encode(&module);
    let re_decoded = bytecode::decode(&re_encoded).expect("encode output must decode");
    let first = verify::verify(&module).is_ok();
    let second = verify::verify(&re_decoded).is_ok();
    assert_eq!(first, second, "verify verdict changed across an encode/decode roundtrip");
});
