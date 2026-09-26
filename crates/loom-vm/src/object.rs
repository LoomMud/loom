// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! Object table: a slab of objects addressed by generational ids (§3.4).

use std::collections::HashMap;
use std::rc::Rc;

use crate::program::Program;
use crate::value::Value;

/// 64-bit generational handle: stale ids (to a freed slot) are detectable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ObjectId {
    pub index: u32,
    pub generation: u32,
}

/// Object variables keyed by (declaring program path, variable name), so
/// hot reload can match them by declaring program and name (§7.2).
pub type Vars = HashMap<Rc<str>, HashMap<Rc<str>, Value>>;

pub struct Object {
    /// `/std/sword` (blueprint) or `/std/sword#12` (clone).
    pub name: String,
    pub program: Rc<Program>,
    pub vars: Vars,
    pub env: Option<ObjectId>,
    pub inventory: Vec<ObjectId>,
    /// Connection bound to this object (interactive), if any.
    pub conn: Option<u64>,
}

struct Slot {
    generation: u32,
    obj: Option<Object>,
}

#[derive(Default)]
pub struct ObjectTable {
    slots: Vec<Slot>,
    free: Vec<u32>,
}

impl ObjectTable {
    pub fn insert(&mut self, obj: Object) -> ObjectId {
        if let Some(index) = self.free.pop() {
            let slot = &mut self.slots[index as usize];
            slot.generation = slot.generation.wrapping_add(1);
            slot.obj = Some(obj);
            ObjectId {
                index,
                generation: slot.generation,
            }
        } else {
            let index = self.slots.len() as u32;
            self.slots.push(Slot {
                generation: 0,
                obj: Some(obj),
            });
            ObjectId {
                index,
                generation: 0,
            }
        }
    }

    pub fn get(&self, id: ObjectId) -> Option<&Object> {
        self.slots
            .get(id.index as usize)
            .filter(|s| s.generation == id.generation)
            .and_then(|s| s.obj.as_ref())
    }

    pub fn get_mut(&mut self, id: ObjectId) -> Option<&mut Object> {
        self.slots
            .get_mut(id.index as usize)
            .filter(|s| s.generation == id.generation)
            .and_then(|s| s.obj.as_mut())
    }

    /// Remove an object; its id becomes stale.
    pub fn remove(&mut self, id: ObjectId) -> Option<Object> {
        let slot = self.slots.get_mut(id.index as usize)?;
        if slot.generation != id.generation {
            return None;
        }
        let obj = slot.obj.take()?;
        self.free.push(id.index);
        Some(obj)
    }

    pub fn ids(&self) -> Vec<ObjectId> {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.obj.is_some())
            .map(|(i, s)| ObjectId {
                index: i as u32,
                generation: s.generation,
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.obj.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
