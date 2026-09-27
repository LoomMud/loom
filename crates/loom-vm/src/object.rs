// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! The object id type shared by the object/program registry (§3.4).
//!
//! The generational slab itself lives in [`crate::bcvm::registry::Registry`]
//! ([`crate::bcvm::registry::BcObject`]); this module only keeps the id
//! type so `bcvm` does not need to depend on `world`, and `world` does not
//! need to depend on `bcvm::registry` for just the id.

/// 64-bit generational handle: stale ids (to a freed slot) are detectable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ObjectId {
    pub index: u32,
    pub generation: u32,
}
