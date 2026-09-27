// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! V7 micro-benchmark (OBI-72): times a few Weft workloads through the
//! public `World` API only (`boot_with_limits`, `find_object`, `call`), so
//! the identical file runs against the Phase 0 tree-walker (pre-OBI-72
//! `main`) and the bytecode VM. No external deps; std `Instant` timing.
//!
//! `cargo run --release -p loom-vm --example vm_bench [iters]`

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
    for (rel, src) in [("secure/master.wf", MASTER), ("bench/b.wf", B)] {
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
    for w in ["arith", "recurse", "strings", "containers", "cross_object"] {
        let first = world
            .call(master, w, vec![], &mut NullHost)
            .unwrap_or_else(|e| panic!("{w}: {e}"));
        let shown = world.display(&first);
        let mut t: Vec<Duration> = (0..iters)
            .map(|_| {
                let s = Instant::now();
                world.call(master, w, vec![], &mut NullHost).unwrap();
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
