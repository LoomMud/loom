// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Binary world snapshots (design spec §8.1 model 2, OBI-173): the base
//! for copyover (P2-O1). A snapshot is a versioned byte stream that
//! round-trips a [`crate::world::World`]'s *object graph* (object
//! vars/placement/connections) -- never a program's bytecode, which the
//! standby process always recompiles fresh from `mudlib_root` on load,
//! exactly like [`crate::world::World::boot`] would.
//!
//! **The copy-on-write split (spec §8.1 "incrementally with copy-on-write
//! so the tick is not paused for the whole write"):**
//!
//! 1. [`crate::world::World::begin_snapshot`] calls
//!    [`crate::bcvm::registry::Registry::capture`], which clones every
//!    live object's `Rc`s (vars, inventory, program pointer) -- `O(object
//!    count)` pointer bumps, not `O(bytes)`. This is the *only*
//!    synchronous work charged to the world thread; `capture`'s result
//!    does not borrow the registry, so `World::tick` can keep running
//!    immediately after.
//! 2. The returned [`SnapshotJob`] encodes that captured graph into bytes
//!    via repeated [`SnapshotJob::encode_step`] calls, each bounded by a
//!    caller-supplied slot budget -- meant to be driven a little at a time
//!    between ticks (or in one shot via [`SnapshotJob::encode_all`] when a
//!    single pause is acceptable, e.g. in a test). This is safe to spread
//!    across many ticks' worth of further live mutation because every
//!    `Value` is immutable-once-shared (`crate::bcvm::heap` module docs):
//!    a live write anywhere in the registry clones its buffer through
//!    `Rc::make_mut` rather than mutating through the snapshot's own `Rc`.
//!
//! **Known scope limits (flagged, not hidden -- OBI-173):**
//! - A live function value (a closure, or a named function reference
//!   stored in a var) cannot be encoded yet: it references this process's
//!   own `Rc<dyn ProgramCode>`, which has no serialized form. Encoding one
//!   is a clean [`SnapshotError::UnsupportedValue`], not a panic. None of
//!   the `/std/item`-style exit-criterion fixtures store one in a var.
//! - The scheduler (pending `call_out`s/heartbeat subscriptions) and
//!   security/roles state are **not** part of this snapshot -- scope here
//!   is "the full object graph" per the issue; a real copyover (O1) needs
//!   to decide separately whether in-flight `call_out`s survive a
//!   restart or are simply re-armed by each object's own `create()`/
//!   `reset()` after reload.

use std::collections::HashMap;
use std::rc::Rc;

use crate::bcvm::heap::{EnumVal, HeapObj, MapData, StructVal, Value};
use crate::bcvm::registry::{BcObject, RegistrySnapshot};
use crate::object::ObjectId;
use crate::security::Sym;

/// `(declaring program path, var name)` plus its restored value -- one
/// entry of [`DecodedObject::vars`].
pub type DecodedVar = ((Rc<str>, Rc<str>), Value);

/// 8-byte file magic: any file not starting with this is rejected before
/// anything else is even parsed.
pub const SNAPSHOT_MAGIC: [u8; 8] = *b"LOOMSNAP";

/// The on-disk framing's own version (section order/sizes). Bumped
/// whenever the *framing* changes shape, independent of
/// [`SNAPSHOT_ABI_VERSION`] (which tracks the VM's value/object
/// representation).
pub const SNAPSHOT_FORMAT_VERSION: u16 = 1;

/// Bumped whenever a change to `Value`/`BcObject`/`Registry`'s shape would
/// make an older snapshot unsafe to decode as this one (spec §8.1
/// "versioned format; a load from an incompatible ABI fails cleanly").
/// Every encode writes the *current* build's version; every decode
/// rejects anything else outright -- there is deliberately no partial
/// forward/backward compatibility in v1 (copyover's two sides are always
/// the same build).
pub const SNAPSHOT_ABI_VERSION: u16 = 1;

/// Anything that can go wrong writing or reading a snapshot. Every
/// variant is a clean, reportable error -- nothing in this module panics
/// on untrusted/corrupt input (this is a trust boundary: a snapshot file
/// is attacker-reachable the moment it touches disk or a copyover
/// channel).
#[derive(Debug)]
pub enum SnapshotError {
    /// [`crate::bcvm::registry::Registry::capture`] was called while an
    /// `atomic fn` scope was open.
    AtomicScopeOpen,
    /// A value kind this build cannot encode yet (see module docs).
    UnsupportedValue(&'static str),
    /// The byte stream ended before a section's declared/implied length.
    Truncated(&'static str),
    /// The first 8 bytes are not [`SNAPSHOT_MAGIC`].
    BadMagic,
    /// [`SNAPSHOT_ABI_VERSION`] mismatch.
    UnsupportedAbi { found: u16, supported: u16 },
    /// Well-framed but internally inconsistent bytes (bad tag, invalid
    /// UTF-8, ...).
    Corrupt(String),
    /// Decoded cleanly, but could not be turned back into a live
    /// `Registry` (e.g. a program path that no longer compiles against
    /// the standby's `mudlib_root`).
    Restore(String),
    /// A `Value` nested more than [`MAX_VALUE_NESTING`] containers deep,
    /// either while encoding a live value or while decoding bytes
    /// (PR #69 review, OBI-173 R1): a crafted/corrupt input can otherwise
    /// recurse the native stack straight through its guard page and
    /// abort the process rather than failing cleanly, same trust-boundary
    /// concern as every other variant here.
    NestingTooDeep,
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotError::AtomicScopeOpen => {
                write!(f, "cannot snapshot while an atomic fn scope is open")
            }
            SnapshotError::UnsupportedValue(kind) => write!(
                f,
                "snapshot cannot encode a live {kind} value yet (OBI-173 known limitation)"
            ),
            SnapshotError::Truncated(what) => {
                write!(f, "snapshot file is truncated: missing {what}")
            }
            SnapshotError::BadMagic => write!(f, "not a loom world snapshot file (bad magic)"),
            SnapshotError::UnsupportedAbi { found, supported } => write!(
                f,
                "snapshot ABI version {found} is not supported by this driver build \
                 (supports {supported}); the standby side of a copyover must run the \
                 exact same driver build as the side that wrote this snapshot"
            ),
            SnapshotError::Corrupt(msg) => write!(f, "snapshot file is corrupt: {msg}"),
            SnapshotError::Restore(msg) => write!(f, "cannot restore snapshot: {msg}"),
            SnapshotError::NestingTooDeep => write!(
                f,
                "snapshot value nesting exceeds the {MAX_VALUE_NESTING}-container limit"
            ),
        }
    }
}

impl std::error::Error for SnapshotError {}

// ---------------------------------------------------------------------
// Primitive byte writers
// ---------------------------------------------------------------------

fn w_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}
fn w_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn w_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn w_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn w_i64(out: &mut Vec<u8>, v: i64) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn w_f64(out: &mut Vec<u8>, v: f64) {
    out.extend_from_slice(&v.to_bits().to_le_bytes());
}
fn w_bytes(out: &mut Vec<u8>, b: &[u8]) {
    w_u32(out, b.len() as u32);
    out.extend_from_slice(b);
}
fn w_str(out: &mut Vec<u8>, s: &str) {
    w_bytes(out, s.as_bytes());
}
fn w_obj_id(out: &mut Vec<u8>, id: ObjectId) {
    w_u32(out, id.index);
    w_u32(out, id.generation);
}
fn w_opt_obj_id(out: &mut Vec<u8>, id: Option<ObjectId>) {
    match id {
        Some(id) => {
            w_u8(out, 1);
            w_obj_id(out, id);
        }
        None => w_u8(out, 0),
    }
}

// ---------------------------------------------------------------------
// Primitive byte reader
// ---------------------------------------------------------------------

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], SnapshotError> {
        if self.pos + n > self.buf.len() {
            return Err(SnapshotError::Truncated(what));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Bytes left in the stream -- an upper bound on how many *elements*
    /// a length-prefixed section can possibly hold (every element is at
    /// least one byte), used to clamp an untrusted count before it is
    /// handed to `Vec::with_capacity`/`HashMap::with_capacity` (PR #69
    /// review, OBI-173 R1: a crafted file's declared count must not be
    /// able to request an allocation far larger than the bytes actually
    /// available, which can abort the process rather than failing
    /// cleanly).
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn u8(&mut self) -> Result<u8, SnapshotError> {
        Ok(self.take(1, "u8")?[0])
    }
    fn u16(&mut self) -> Result<u16, SnapshotError> {
        Ok(u16::from_le_bytes(self.take(2, "u16")?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, SnapshotError> {
        Ok(u32::from_le_bytes(self.take(4, "u32")?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, SnapshotError> {
        Ok(u64::from_le_bytes(self.take(8, "u64")?.try_into().unwrap()))
    }
    fn i64(&mut self) -> Result<i64, SnapshotError> {
        Ok(i64::from_le_bytes(self.take(8, "i64")?.try_into().unwrap()))
    }
    fn f64(&mut self) -> Result<f64, SnapshotError> {
        Ok(f64::from_bits(self.u64()?))
    }
    /// A trusted element count to preallocate with: never more than the
    /// bytes actually remaining in the stream, so a bogus huge count in a
    /// small/truncated buffer clamps down to a small, harmless
    /// allocation instead of requesting (and aborting the process on)
    /// tens of gigabytes.
    fn bounded_count(&self, n: u32) -> usize {
        (n as usize).min(self.remaining())
    }

    fn bytes(&mut self) -> Result<Vec<u8>, SnapshotError> {
        let n = self.u32()? as usize;
        Ok(self.take(n, "length-prefixed bytes")?.to_vec())
    }
    fn string(&mut self) -> Result<String, SnapshotError> {
        let b = self.bytes()?;
        String::from_utf8(b).map_err(|e| SnapshotError::Corrupt(e.to_string()))
    }
    fn obj_id(&mut self) -> Result<ObjectId, SnapshotError> {
        Ok(ObjectId {
            index: self.u32()?,
            generation: self.u32()?,
        })
    }
    fn opt_obj_id(&mut self) -> Result<Option<ObjectId>, SnapshotError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.obj_id()?)),
            t => Err(SnapshotError::Corrupt(format!("bad option tag {t}"))),
        }
    }
}

// ---------------------------------------------------------------------
// Value encode/decode
// ---------------------------------------------------------------------

/// Container nesting limit shared by [`encode_value`]/[`decode_value`]
/// (PR #69 review, OBI-173 R1): neither recurses without bound, so a
/// crafted/corrupt input (or a pathologically deep live value) cannot
/// blow the native stack and abort the process -- it gets a clean
/// [`SnapshotError::NestingTooDeep`] instead. Chosen to match
/// [`crate::bcvm::vm::Limits::max_depth`]'s own default (512): there is
/// no separate "container nesting" limit elsewhere in the VM to reuse, so
/// this mirrors the Weft call-depth default per the review's own
/// fallback.
const MAX_VALUE_NESTING: usize = 512;

fn encode_value(v: &Value, out: &mut Vec<u8>) -> Result<(), SnapshotError> {
    encode_value_at(v, out, 0)
}

fn encode_value_at(v: &Value, out: &mut Vec<u8>, depth: usize) -> Result<(), SnapshotError> {
    if depth > MAX_VALUE_NESTING {
        return Err(SnapshotError::NestingTooDeep);
    }
    match v {
        Value::Null => w_u8(out, 0),
        Value::Bool(b) => {
            w_u8(out, 1);
            w_u8(out, *b as u8);
        }
        Value::Int(n) => {
            w_u8(out, 2);
            w_i64(out, *n);
        }
        Value::Float(n) => {
            w_u8(out, 3);
            w_f64(out, *n);
        }
        Value::Object(id) => {
            w_u8(out, 4);
            w_obj_id(out, *id);
        }
        Value::Heap(h) => match &**h {
            HeapObj::Str(s) => {
                w_u8(out, 5);
                w_str(out, s);
            }
            HeapObj::Array(a) => {
                w_u8(out, 6);
                w_u32(out, a.items().len() as u32);
                for item in a.items() {
                    encode_value_at(item, out, depth + 1)?;
                }
            }
            HeapObj::Map(m) => {
                w_u8(out, 7);
                w_u32(out, m.entries.len() as u32);
                for (k, v) in &m.entries {
                    encode_value_at(k, out, depth + 1)?;
                    encode_value_at(v, out, depth + 1)?;
                }
            }
            HeapObj::Struct(s) => {
                w_u8(out, 8);
                w_str(out, &s.module);
                w_str(out, &s.name);
                w_u32(out, s.fields.len() as u32);
                for (name, val) in &s.fields {
                    w_str(out, name);
                    encode_value_at(val, out, depth + 1)?;
                }
            }
            HeapObj::Enum(e) => {
                w_u8(out, 9);
                w_str(out, &e.module);
                w_str(out, &e.name);
                w_str(out, &e.variant);
                w_u32(out, e.payload.len() as u32);
                for val in &e.payload {
                    encode_value_at(val, out, depth + 1)?;
                }
            }
            HeapObj::Fn(_) => return Err(SnapshotError::UnsupportedValue("function")),
        },
    }
    Ok(())
}

fn decode_value(c: &mut Cursor) -> Result<Value, SnapshotError> {
    decode_value_at(c, 0)
}

fn decode_value_at(c: &mut Cursor, depth: usize) -> Result<Value, SnapshotError> {
    if depth > MAX_VALUE_NESTING {
        return Err(SnapshotError::NestingTooDeep);
    }
    let tag = c.u8()?;
    Ok(match tag {
        0 => Value::Null,
        1 => Value::Bool(c.u8()? != 0),
        2 => Value::Int(c.i64()?),
        3 => Value::Float(c.f64()?),
        4 => Value::Object(c.obj_id()?),
        5 => Value::str(&c.string()?),
        6 => {
            let n = c.u32()?;
            let mut items = Vec::with_capacity(c.bounded_count(n));
            for _ in 0..n {
                items.push(decode_value_at(c, depth + 1)?);
            }
            Value::array(items)
        }
        7 => {
            let n = c.u32()?;
            let mut m = MapData::default();
            for _ in 0..n {
                let k = decode_value_at(c, depth + 1)?;
                let v = decode_value_at(c, depth + 1)?;
                m.insert(k, v);
            }
            Value::map(m)
        }
        8 => {
            let module: Rc<str> = c.string()?.into();
            let name: Rc<str> = c.string()?.into();
            let n = c.u32()?;
            let mut fields = Vec::with_capacity(c.bounded_count(n));
            for _ in 0..n {
                let fname: Rc<str> = c.string()?.into();
                let v = decode_value_at(c, depth + 1)?;
                fields.push((fname, v));
            }
            Value::struct_val(StructVal {
                module,
                name,
                fields,
            })
        }
        9 => {
            let module: Rc<str> = c.string()?.into();
            let name: Rc<str> = c.string()?.into();
            let variant: Rc<str> = c.string()?.into();
            let n = c.u32()?;
            let mut payload = Vec::with_capacity(c.bounded_count(n));
            for _ in 0..n {
                payload.push(decode_value_at(c, depth + 1)?);
            }
            Value::enum_val(EnumVal {
                module,
                name,
                variant,
                payload,
            })
        }
        t => return Err(SnapshotError::Corrupt(format!("bad value tag {t}"))),
    })
}

// ---------------------------------------------------------------------
// Object/meta encode
// ---------------------------------------------------------------------

fn encode_object(o: &BcObject, out: &mut Vec<u8>) -> Result<(), SnapshotError> {
    w_str(out, &o.name);
    w_str(out, &o.program.path);
    w_u32(out, o.vars.len() as u32);
    for ((decl, name), val) in &o.vars {
        w_str(out, decl);
        w_str(out, name);
        encode_value(val, out)?;
    }
    w_opt_obj_id(out, o.env);
    w_u32(out, o.inventory.len() as u32);
    for id in &o.inventory {
        w_obj_id(out, *id);
    }
    match o.conn {
        Some(conn) => {
            w_u8(out, 1);
            w_u64(out, conn);
        }
        None => w_u8(out, 0),
    }
    w_u32(out, o.uid);
    w_u32(out, o.euid);
    w_u32(out, o.owner);
    Ok(())
}

fn encode_meta(snap: &RegistrySnapshot, out: &mut Vec<u8>) {
    w_u64(out, snap.next_clone);
    w_u64(out, snap.next_bind_seq);
    w_u64(out, snap.rng_state);
    w_u32(out, snap.free.len() as u32);
    for f in &snap.free {
        w_u32(out, *f);
    }
    w_u32(out, snap.names.len() as u32);
    for (name, id) in &snap.names {
        w_str(out, name);
        w_obj_id(out, *id);
    }
    w_u32(out, snap.conns.len() as u32);
    for (conn, id) in &snap.conns {
        w_u64(out, *conn);
        w_obj_id(out, *id);
    }
    w_u32(out, snap.bind_seq.len() as u32);
    for (conn, seq) in &snap.bind_seq {
        w_u64(out, *conn);
        w_u64(out, *seq);
    }
    w_u32(out, snap.sym_names.len() as u32);
    for n in &snap.sym_names {
        w_str(out, n);
    }
}

/// A binary snapshot encode in progress: owns a captured, independent copy
/// of the object graph ([`RegistrySnapshot`]) and encodes it a bounded
/// chunk at a time. See the module docs for the copy-on-write story this
/// implements.
pub struct SnapshotJob {
    snap: RegistrySnapshot,
    next_slot: usize,
    header_written: bool,
}

impl SnapshotJob {
    pub fn new(snap: RegistrySnapshot) -> Self {
        SnapshotJob {
            snap,
            next_slot: 0,
            header_written: false,
        }
    }

    /// Total slots (live + free) the captured registry had -- an upper
    /// bound on how many `encode_step` calls (at `max_slots == 1`) it
    /// takes to finish.
    pub fn total_slots(&self) -> usize {
        self.snap.slots.len()
    }

    /// Live object count at capture time (tests/metrics).
    pub fn object_count(&self) -> usize {
        self.snap.slots.iter().filter(|(_, o)| o.is_some()).count()
    }

    pub fn is_done(&self) -> bool {
        self.header_written && self.next_slot >= self.snap.slots.len()
    }

    /// Encode the header+metadata (first call only) plus up to
    /// `max_slots` more object slots into `out`, returning how many slots
    /// were encoded this call (`0` once [`SnapshotJob::is_done`]).
    ///
    /// Meant to be called repeatedly with a small `max_slots` budget --
    /// e.g. once per `World::tick` -- so encoding a large world's worth
    /// of bytes never blocks any single tick for long; see the module
    /// docs for why this is safe to interleave with further live
    /// mutation.
    pub fn encode_step(
        &mut self,
        out: &mut Vec<u8>,
        max_slots: usize,
    ) -> Result<usize, SnapshotError> {
        if !self.header_written {
            out.extend_from_slice(&SNAPSHOT_MAGIC);
            w_u16(out, SNAPSHOT_FORMAT_VERSION);
            w_u16(out, SNAPSHOT_ABI_VERSION);
            w_u32(out, self.snap.slots.len() as u32);
            encode_meta(&self.snap, out);
            self.header_written = true;
        }
        let end = (self.next_slot + max_slots).min(self.snap.slots.len());
        let mut n = 0;
        for i in self.next_slot..end {
            let (generation, obj) = &self.snap.slots[i];
            w_u32(out, *generation);
            match obj {
                None => w_u8(out, 0),
                Some(o) => {
                    w_u8(out, 1);
                    encode_object(o, out)?;
                }
            }
            n += 1;
        }
        self.next_slot = end;
        Ok(n)
    }

    /// Encode the whole job in one call (tests, or a driver that has
    /// decided a single pause is acceptable).
    pub fn encode_all(mut self) -> Result<Vec<u8>, SnapshotError> {
        let mut out = Vec::new();
        while !self.is_done() {
            self.encode_step(&mut out, usize::MAX)?;
        }
        Ok(out)
    }
}

/// One restored object's dynamic state, with its program identified only
/// by path (`crate::bcvm::registry::Registry::restore` resolves this to a
/// live `Rc<CompiledProgram>` by compiling/looking it up against the
/// loading process's own `mudlib_root`).
pub struct DecodedObject {
    pub name: String,
    pub program_path: String,
    pub vars: Vec<DecodedVar>,
    pub env: Option<ObjectId>,
    pub inventory: Vec<ObjectId>,
    pub conn: Option<u64>,
    pub uid: Sym,
    pub euid: Sym,
    pub owner: Sym,
}

/// A decoded snapshot, ready for
/// [`crate::bcvm::registry::Registry::restore`].
pub struct DecodedSnapshot {
    pub slots: Vec<(u32, Option<DecodedObject>)>,
    pub free: Vec<u32>,
    pub names: HashMap<String, ObjectId>,
    pub next_clone: u64,
    pub conns: HashMap<u64, ObjectId>,
    pub bind_seq: HashMap<u64, u64>,
    pub next_bind_seq: u64,
    pub rng_state: u64,
    pub sym_names: Vec<String>,
}

fn decode_object(c: &mut Cursor) -> Result<DecodedObject, SnapshotError> {
    let name = c.string()?;
    let program_path = c.string()?;
    let vars_count = c.u32()? as usize;
    let mut vars = Vec::with_capacity(vars_count.min(c.remaining()));
    for _ in 0..vars_count {
        let decl: Rc<str> = c.string()?.into();
        let var_name: Rc<str> = c.string()?.into();
        let val = decode_value(c)?;
        vars.push(((decl, var_name), val));
    }
    let env = c.opt_obj_id()?;
    let inv_count = c.u32()? as usize;
    let mut inventory = Vec::with_capacity(inv_count.min(c.remaining()));
    for _ in 0..inv_count {
        inventory.push(c.obj_id()?);
    }
    let has_conn = c.u8()?;
    let conn = if has_conn == 1 { Some(c.u64()?) } else { None };
    let uid = c.u32()?;
    let euid = c.u32()?;
    let owner = c.u32()?;
    Ok(DecodedObject {
        name,
        program_path,
        vars,
        env,
        inventory,
        conn,
        uid,
        euid,
        owner,
    })
}

/// Parse a byte stream written by [`SnapshotJob`] into a
/// [`DecodedSnapshot`]. Fails cleanly (never panics) on a bad magic
/// ([`SnapshotError::BadMagic`]), an incompatible ABI
/// ([`SnapshotError::UnsupportedAbi`]), or a truncated/corrupt stream
/// (spec §8.1 "a load from an incompatible ABI fails cleanly").
pub fn decode_snapshot(bytes: &[u8]) -> Result<DecodedSnapshot, SnapshotError> {
    let mut c = Cursor::new(bytes);
    let magic = c.take(8, "magic")?;
    if magic != SNAPSHOT_MAGIC {
        return Err(SnapshotError::BadMagic);
    }
    let _format_version = c.u16()?;
    let abi = c.u16()?;
    if abi != SNAPSHOT_ABI_VERSION {
        return Err(SnapshotError::UnsupportedAbi {
            found: abi,
            supported: SNAPSHOT_ABI_VERSION,
        });
    }
    let slot_count = c.u32()? as usize;
    let next_clone = c.u64()?;
    let next_bind_seq = c.u64()?;
    let rng_state = c.u64()?;

    let free_count = c.u32()? as usize;
    let mut free = Vec::with_capacity(free_count.min(c.remaining()));
    for _ in 0..free_count {
        free.push(c.u32()?);
    }

    let names_count = c.u32()? as usize;
    let mut names = HashMap::with_capacity(names_count.min(c.remaining()));
    for _ in 0..names_count {
        let name = c.string()?;
        let id = c.obj_id()?;
        names.insert(name, id);
    }

    let conns_count = c.u32()? as usize;
    let mut conns = HashMap::with_capacity(conns_count.min(c.remaining()));
    for _ in 0..conns_count {
        let conn = c.u64()?;
        let id = c.obj_id()?;
        conns.insert(conn, id);
    }

    let bind_seq_count = c.u32()? as usize;
    let mut bind_seq = HashMap::with_capacity(bind_seq_count.min(c.remaining()));
    for _ in 0..bind_seq_count {
        let conn = c.u64()?;
        let seq = c.u64()?;
        bind_seq.insert(conn, seq);
    }

    let sym_count = c.u32()? as usize;
    let mut sym_names = Vec::with_capacity(sym_count.min(c.remaining()));
    for _ in 0..sym_count {
        sym_names.push(c.string()?);
    }

    let mut slots = Vec::with_capacity(slot_count.min(c.remaining()));
    for _ in 0..slot_count {
        let generation = c.u32()?;
        let has_obj = c.u8()?;
        let obj = if has_obj == 1 {
            Some(decode_object(&mut c)?)
        } else {
            None
        };
        slots.push((generation, obj));
    }

    Ok(DecodedSnapshot {
        slots,
        free,
        names,
        next_clone,
        conns,
        bind_seq,
        next_bind_seq,
        rng_state,
        sym_names,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PR #69 review item 1: a crafted file can declare a `free_count`
    /// (or any other length-prefixed count) far larger than the bytes
    /// actually backing it. Before the fix this fed straight into
    /// `Vec::with_capacity`, which can abort the whole process on an
    /// allocation failure for an untrusted input that never touched the
    /// heap otherwise. After the fix the capacity is clamped to the
    /// remaining byte count, and the stream still fails -- cleanly, as a
    /// typed [`SnapshotError`] -- once it actually runs out of bytes.
    #[test]
    fn huge_declared_count_in_a_tiny_buffer_is_a_typed_error_not_an_abort() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&SNAPSHOT_MAGIC);
        bytes.extend_from_slice(&SNAPSHOT_FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&SNAPSHOT_ABI_VERSION.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes()); // slot_count
        bytes.extend_from_slice(&0u64.to_le_bytes()); // next_clone
        bytes.extend_from_slice(&0u64.to_le_bytes()); // next_bind_seq
        bytes.extend_from_slice(&0u64.to_le_bytes()); // rng_state
        // free_count: a crafted file asking for ~4 billion `u32`s (~16GB)
        // with zero bytes left in the stream to back them.
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());

        let err = decode_snapshot(&bytes)
            .err()
            .expect("a huge declared count backed by a tiny buffer must not decode");
        assert!(matches!(err, SnapshotError::Truncated(_)), "{err:?}");
    }

    /// Same bug, a different section: a `vars`/`inventory` count inside an
    /// object record is just as untrusted as the top-level ones.
    #[test]
    fn huge_object_section_count_in_a_tiny_buffer_is_a_typed_error_not_an_abort() {
        let mut bytes = Vec::new();
        w_str(&mut bytes, "thing"); // name
        w_str(&mut bytes, "/std/thing"); // program_path
        // vars_count: huge, with nothing behind it.
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        let mut c = Cursor::new(&bytes);
        let err = decode_object(&mut c)
            .err()
            .expect("a huge vars count backed by a tiny buffer must not decode");
        assert!(matches!(err, SnapshotError::Truncated(_)), "{err:?}");
    }

    /// PR #69 review item 2: `encode_value`/`decode_value` recursed with
    /// no depth limit, so a deeply nested live value (encode side) or a
    /// crafted deeply-nested byte stream (decode side) could blow the
    /// native stack and abort the process instead of failing cleanly.
    #[test]
    fn deeply_nested_value_is_a_typed_error_on_both_the_encode_and_decode_path() {
        // Run on a dedicated, generously-sized stack: this test's own
        // *fixture* (an owned, ~530-deep nested `Value`) recurses on drop
        // (plain compiler-generated drop glue, unrelated to the bounded
        // `encode_value`/`decode_value` under test here), which is enough
        // to overflow a default debug-build test-thread stack on its own.
        // The guard this test actually exists to prove -- that
        // `encode_value`/`decode_value` refuse to recurse past
        // `MAX_VALUE_NESTING` in the first place -- does not depend on
        // the stack size at all.
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                // Encode side: a value nested well past the limit, built
                // iteratively (not recursively) so *building* it can't
                // itself blow the stack.
                let mut v = Value::Int(0);
                for _ in 0..(MAX_VALUE_NESTING + 16) {
                    v = Value::array(vec![v]);
                }
                let mut out = Vec::new();
                let err =
                    encode_value(&v, &mut out).expect_err("nesting limit must trip on encode");
                assert!(matches!(err, SnapshotError::NestingTooDeep), "{err:?}");

                // Decode side: a byte stream of nothing but "array of one
                // item" tags, deep enough to trip the same limit before
                // the stream ever runs out of bytes -- this is testing
                // the depth guard itself, not truncation.
                let mut bytes = Vec::new();
                for _ in 0..(MAX_VALUE_NESTING + 16) {
                    w_u8(&mut bytes, 6); // array tag
                    w_u32(&mut bytes, 1); // one item
                }
                w_u8(&mut bytes, 0); // innermost element: Null
                let mut c = Cursor::new(&bytes);
                let err = decode_value(&mut c).expect_err("nesting limit must trip on decode");
                assert!(matches!(err, SnapshotError::NestingTooDeep), "{err:?}");
            })
            .expect("spawn test thread")
            .join()
            .expect("test thread panicked");
    }
}
