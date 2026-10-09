// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! OBI-369 scratch probe. Deliberately fails, in the crate cargo reaches
//! first in workspace order, to prove the `rust` lane no longer stops there.
//! This file exists on a throwaway branch and is never merged.

#[test]
fn ci_lane_probe() {
    // Env-var rather than `assert!(false)` so clippy's
    // `assertions_on_constants` doesn't fail the lane's clippy step *before*
    // the test step -- the probe has to fail in `cargo test`, not in clippy.
    let probe_should_fail = std::env::var_os("LOOM_CI_LANE_PROBE_MUST_FAIL").is_some();
    assert!(
        probe_should_fail,
        "OBI-369 lane probe: intentional failure in loom-cli, the first test target"
    );
}
