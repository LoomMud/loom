// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! V7 micro-benchmark (OBI-72): times a few Weft workloads through the
//! public `World` API only (`boot_with_limits`, `find_object`, `call`), so
//! the identical file runs against the Phase 0 tree-walker (pre-OBI-72
//! `main`) and the bytecode VM. No external deps; std `Instant` timing.
//!
//! `cargo run --release -p loom-vm --example vm_bench [iters]`
//!
//! **Per-call-site inline cache (OBI-78):** `monocall`/`monocall_other`
//! below are dedicated, low-payload-per-call workloads (a virtual
//! self-call and a `CallOther`, in a tight loop) whose time is almost
//! entirely call *dispatch* overhead, not the callee's body — the
//! workload the inline cache in `bcvm::registry::RegistryHost::dispatch`
//! targets. Set `LOOM_VM_DISABLE_INLINE_CACHE=1` to get the pre-cache
//! baseline numbers from this same binary (every call re-does the
//! dispatch-table hash lookup) for an A/B comparison:
//! `cargo run --release -p loom-vm --example vm_bench` vs.
//! `LOOM_VM_DISABLE_INLINE_CACHE=1 cargo run --release -p loom-vm --example vm_bench`.

use std::time::{Duration, Instant};

use loom_vm::{Limits, NullHost, World};

const MASTER: &str = r#"
fn fib(n: int) -> int {
    if n < 2 {
        return n
    }
    return fib(n - 1) + fib(n - 2)
}

fn arith() -> any {
    var i = 0
    var acc = 0
    while i < 200000 {
        acc = acc + i * 3 % 7
        i += 1
    }
    return acc
}

fn recurse() -> any {
    return fib(20)
}

fn strings() -> any {
    var i = 0
    var s = ""
    while i < 5000 {
        s = s + "x"
        i += 1
    }
    return len(s)
}

fn containers() -> any {
    var i = 0
    var m: {int: int} = {:}
    while i < 5000 {
        m[i] = i * 2
        i += 1
    }
    var total = 0
    for k in keys(m) {
        total += m[k] ?? 0
    }
    return total
}

// Same shape at 10x the entry count (OBI-74 acceptance: sub-quadratic at
// 5k *and* 50k). If `MapData`'s lookup were still the O(n) linear scan
// this replaced, going 5k -> 50k would cost ~100x, not ~10x.
fn containers_50k() -> any {
    var i = 0
    var m: {int: int} = {:}
    while i < 50000 {
        m[i] = i * 2
        i += 1
    }
    var total = 0
    for k in keys(m) {
        total += m[k] ?? 0
    }
    return total
}

fn cross_object() -> any {
    let b = load_object("/bench/b")
    var i = 0
    var acc = 0
    while i < 20000 {
        acc = b.inc(acc)
        i += 1
    }
    return acc
}

fn noop(n: int) -> int {
    return n
}

// Virtual self-dispatch, monomorphic call site, trivial callee: isolates
// `Op::Call` dispatch overhead from everything else (spec §5.8 inline
// cache, OBI-78).
fn monocall() -> any {
    var i = 0
    var acc = 0
    while i < 500000 {
        acc = noop(acc) + 1
        i += 1
    }
    return acc
}

// Same, but `CallOther` (through the object table) instead of virtual
// self-dispatch.
fn monocall_other() -> any {
    let b = load_object("/bench/b")
    var i = 0
    var acc = 0
    while i < 500000 {
        acc = b.inc(acc)
        i += 1
    }
    return acc
}
"#;

// OBI-35 stack-check workloads run on objects under /builders/<u>/ (uid
// `u`), so every gated efun really goes through the guard set + master
// policy cache. `seteuid(own euid)` is the cheapest gated efun with no I/O:
// valid_efun (P3) + valid_seteuid, no guard growth.
const PRIV_POLICY: &str = r#"
fn valid_efun(name: string, class: int, ob: object) -> bool {
    return true
}

fn valid_seteuid(ob: object, euid: string) -> bool {
    return true
}

fn valid_read(path: string, ob: object, op: string) -> bool {
    return true
}
"#;

const PRIV_B: &str = r#"
pub fn priv_check_hot() -> any {
    var i = 0
    while i < 10000 {
        seteuid("b")
        i += 1
    }
    return i
}

// Control for priv_check_*: the same loop around an ungated P0 efun, so
// (priv_check_hot - priv_control) / 10000 is the per-call cost of the two
// cached checks (valid_efun + valid_seteuid) plus their audit entries.
pub fn priv_control() -> any {
    var i = 0
    while i < 10000 {
        geteuid()
        i += 1
    }
    return i
}

// Same loop with three distinct principals on the stack (b → c → d).
pub fn priv_check_guard3() -> any {
    return load_object("/builders/c/p").relay()
}

// Same loop at call depth 150: the check reads the top guard entry, it
// never walks the stack, so this should match priv_check_hot.
pub fn priv_check_deep() -> any {
    return dive(150)
}

fn dive(n: int) -> int {
    if n == 0 {
        return priv_check_hot()
    }
    return dive(n - 1)
}

// 1000 distinct paths: the harness flushes the policy cache before each
// timed run of priv_miss (every check is a miss: one valid_read apply
// execution), and not before priv_read_hit (every check is a hit). The
// difference between the two is the miss cost; both include the same
// (failed) file open.
pub fn priv_read_hit() -> any {
    var i = 0
    while i < 1000 {
        read_file($"/builders/b/nope{i}")
        i += 1
    }
    return i
}

pub fn priv_miss() -> any {
    return priv_read_hit()
}
"#;

const PRIV_C: &str = r#"
pub fn relay() -> any {
    return load_object("/builders/d/p").hot()
}
"#;

const PRIV_D: &str = r#"
pub fn hot() -> any {
    var i = 0
    while i < 10000 {
        seteuid("d")
        i += 1
    }
    return i
}
"#;

const B: &str = r#"
pub fn inc(n: int) -> int {
    return n + 1
}
"#;

fn main() {
    let iters: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(30);
    // Big native stack so the tree-walker baseline is not stack-limited.
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || run(iters))
        .unwrap()
        .join()
        .unwrap();
}

fn run(iters: usize) {
    let root = std::env::temp_dir().join(format!("loom-vm-bench-{}", std::process::id()));
    let master_src = format!("{MASTER}{PRIV_POLICY}");
    for (rel, src) in [
        ("secure/master.wf", master_src.as_str()),
        ("bench/b.wf", B),
        ("builders/b/p.wf", PRIV_B),
        ("builders/c/p.wf", PRIV_C),
        ("builders/d/p.wf", PRIV_D),
    ] {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, src).unwrap();
    }
    let limits = Limits {
        max_ticks: u64::MAX / 4,
        ..Limits::default()
    };
    let mut world = World::boot_with_limits(&root, limits).expect("boot");
    let master = world.find_object("/secure/master").unwrap();
    println!("| workload | result | median | p95 | min |");
    println!("|---|---|---|---|---|");
    for w in [
        "arith",
        "recurse",
        "strings",
        "containers",
        "containers_50k",
        "cross_object",
        "monocall",
        "monocall_other",
        "priv_control",
        "priv_check_hot",
        "priv_check_guard3",
        "priv_check_deep",
        "priv_read_hit",
        "priv_miss",
    ] {
        let on = if w.starts_with("priv_") {
            world
                .load_object("/builders/b/p", &mut NullHost)
                .unwrap_or_else(|e| panic!("{w}: {e}"))
        } else {
            master
        };
        let flush = w == "priv_miss";
        let first = world
            .call(on, w, vec![], &mut NullHost)
            .unwrap_or_else(|e| panic!("{w}: {e}"));
        let shown = world.display(&first);
        let mut t: Vec<Duration> = (0..iters)
            .map(|_| {
                if flush {
                    world.flush_security_cache();
                }
                let s = Instant::now();
                world.call(on, w, vec![], &mut NullHost).unwrap();
                s.elapsed()
            })
            .collect();
        t.sort();
        let p = |q: f64| t[((t.len() - 1) as f64 * q).round() as usize];
        println!(
            "| {w} | {shown} | {:.3} ms | {:.3} ms | {:.3} ms |",
            p(0.5).as_secs_f64() * 1e3,
            p(0.95).as_secs_f64() * 1e3,
            t[0].as_secs_f64() * 1e3
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}
