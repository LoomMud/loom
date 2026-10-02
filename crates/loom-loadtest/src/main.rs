// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `loom-loadtest`: drives N simulated telnet players against a running
//! `loom serve` with Warp's alpha command mix (R4, OBI-40), measuring
//! command -> prompt latency to prove exit criterion E1.1 (150 players,
//! p99 < 50 ms).
//!
//! Usage:
//!   loom-loadtest --addr 127.0.0.1:4000 --mix path/to/warp/loadbot/mix.tsv \
//!     --players 150 --duration-secs 120 [--out results/run]
//!
//! See `--help` for the full flag list.

mod bot;
mod metrics_scrape;
mod mix;
mod names;
mod report;
mod session;
mod telnet;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::sync::{RwLock, mpsc};
use tokio::time::Instant;

use bot::{BotConfig, Event, run_bot};
use mix::Mix;
use report::{LatencyReport, RunReport, Samples};

struct Args {
    addr: String,
    mix_path: PathBuf,
    players: usize,
    duration_secs: u64,
    ramp_per_sec: f64,
    slow_reader_fraction: f64,
    slow_reader_delay_ms: u64,
    think_min_ms: u64,
    think_max_ms: u64,
    out_prefix: PathBuf,
    sla_p99_ms: f64,
    fail_on_sla_miss: bool,
    password: String,
    class: String,
    seed: u64,
    metrics_url: Option<String>,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut addr = "127.0.0.1:4000".to_string();
        let mut mix_path = None;
        let mut players = 150_usize;
        let mut duration_secs = 120_u64;
        let mut ramp_per_sec = 10.0_f64;
        let mut slow_reader_fraction = 0.1_f64;
        let mut slow_reader_delay_ms = 400_u64;
        let mut think_min_ms = 800_u64;
        let mut think_max_ms = 2500_u64;
        let mut out_prefix = PathBuf::from("results/run");
        let mut sla_p99_ms = 50.0_f64;
        let mut fail_on_sla_miss = false;
        let mut password = "loadtest-pass".to_string();
        let mut class = "warrior".to_string();
        let mut seed = 0_u64;
        let mut metrics_url = None;

        let mut args = std::env::args().skip(1);
        while let Some(a) = args.next() {
            macro_rules! val {
                () => {
                    args.next().ok_or_else(|| format!("{a} needs a value"))?
                };
            }
            match a.as_str() {
                "--addr" => addr = val!(),
                "--mix" => mix_path = Some(PathBuf::from(val!())),
                "--players" => players = val!().parse().map_err(|_| "bad --players")?,
                "--duration-secs" => {
                    duration_secs = val!().parse().map_err(|_| "bad --duration-secs")?
                }
                "--ramp-per-sec" => {
                    ramp_per_sec = val!().parse().map_err(|_| "bad --ramp-per-sec")?
                }
                "--slow-reader-fraction" => {
                    slow_reader_fraction =
                        val!().parse().map_err(|_| "bad --slow-reader-fraction")?
                }
                "--slow-reader-delay-ms" => {
                    slow_reader_delay_ms =
                        val!().parse().map_err(|_| "bad --slow-reader-delay-ms")?
                }
                "--think-min-ms" => {
                    think_min_ms = val!().parse().map_err(|_| "bad --think-min-ms")?
                }
                "--think-max-ms" => {
                    think_max_ms = val!().parse().map_err(|_| "bad --think-max-ms")?
                }
                "--out" => out_prefix = PathBuf::from(val!()),
                "--sla-p99-ms" => sla_p99_ms = val!().parse().map_err(|_| "bad --sla-p99-ms")?,
                "--fail-on-sla-miss" => fail_on_sla_miss = true,
                "--password" => password = val!(),
                "--class" => class = val!(),
                "--seed" => seed = val!().parse().map_err(|_| "bad --seed")?,
                "--metrics-url" => metrics_url = Some(val!()),
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument: {other}")),
            }
        }

        let mix_path = mix_path.ok_or_else(|| "missing required --mix <path>".to_string())?;

        Ok(Self {
            addr,
            mix_path,
            players,
            duration_secs,
            ramp_per_sec,
            slow_reader_fraction,
            slow_reader_delay_ms,
            think_min_ms,
            think_max_ms,
            out_prefix,
            sla_p99_ms,
            fail_on_sla_miss,
            password,
            class,
            seed,
            metrics_url,
        })
    }
}

fn print_help() {
    println!(
        "loom-loadtest --addr <host:port> --mix <path> [options]\n\n\
         Required:\n\
         \x20 --mix <path>                 Path to Warp's loadbot/mix.tsv\n\n\
         Options (defaults shown):\n\
         \x20 --addr 127.0.0.1:4000         Server to connect to\n\
         \x20 --players 150                 Number of simulated players\n\
         \x20 --duration-secs 120           How long to run the mix after login\n\
         \x20 --ramp-per-sec 10             Logins per second\n\
         \x20 --slow-reader-fraction 0.1    Fraction of bots that read slowly\n\
         \x20 --slow-reader-delay-ms 400    Delay before each read for that cohort\n\
         \x20 --think-min-ms 800            Min pause between mix entries\n\
         \x20 --think-max-ms 2500           Max pause between mix entries\n\
         \x20 --out results/run             Output path prefix (.json, .md)\n\
         \x20 --sla-p99-ms 50               E1.1 threshold\n\
         \x20 --fail-on-sla-miss            Exit 1 if p99 exceeds the SLA\n\
         \x20 --password <s>                 Account password for every bot\n\
         \x20 --class warrior               Character class on creation\n\
         \x20 --seed 0                        RNG seed (0 = time-based)\n\
         \x20 --metrics-url <url>           Scrape this loom-http /metrics URL into the report (OBI-177)\n"
    );
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = match Args::parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            print_help();
            std::process::exit(2);
        }
    };

    if let Err(e) = run(args).await {
        eprintln!("loom-loadtest failed: {e}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<(), String> {
    let mix_text = std::fs::read_to_string(&args.mix_path)
        .map_err(|e| format!("reading {}: {e}", args.mix_path.display()))?;
    let mix = Arc::new(Mix::parse(&mix_text).map_err(|e| e.to_string())?);
    tracing::info!(entries = mix.len(), "loaded command mix");

    let base_seed = if args.seed == 0 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    } else {
        args.seed
    };

    let (tx, mut rx) = mpsc::channel::<Event>(4096);
    let peers: Arc<RwLock<Vec<String>>> = Arc::new(RwLock::new(Vec::new()));

    let start = Instant::now();
    let run_until = start + Duration::from_secs(args.duration_secs);
    let ramp_delay = Duration::from_secs_f64(1.0 / args.ramp_per_sec.max(0.01));
    let slow_reader_every = if args.slow_reader_fraction <= 0.0 {
        0
    } else {
        ((1.0 / args.slow_reader_fraction).round() as usize).max(1)
    };

    let mut handles = Vec::with_capacity(args.players);
    for i in 0..args.players {
        let cfg = BotConfig {
            addr: args.addr.clone(),
            name: names::bot_name(i),
            password: args.password.clone(),
            class: args.class.clone(),
            slow_reader: slow_reader_every > 0 && i % slow_reader_every == 0,
            slow_reader_delay: Duration::from_millis(args.slow_reader_delay_ms),
            think_min: Duration::from_millis(args.think_min_ms),
            think_max: Duration::from_millis(args.think_max_ms),
            run_until,
        };
        let mix = Arc::clone(&mix);
        let peers = Arc::clone(&peers);
        let rng = StdRng::seed_from_u64(base_seed.wrapping_add(i as u64));
        let tx = tx.clone();
        handles.push(tokio::spawn(run_bot(cfg, mix, peers, rng, tx)));
        if i + 1 < args.players {
            tokio::time::sleep(ramp_delay).await;
        }
    }
    drop(tx);

    let mut command_latency = Samples::default();
    let mut slow_reader_latency = Samples::default();
    let mut login_latency = Samples::default();
    let mut login_failures = 0_usize;
    let mut disconnects = 0_usize;

    while let Some(event) = rx.recv().await {
        match event {
            Event::LoginOk(d) => login_latency.push(d),
            Event::LoginFailed(reason) => {
                login_failures += 1;
                tracing::warn!(reason, "bot login failed");
            }
            Event::Command(d) => command_latency.push(d),
            Event::SlowReaderCommand(d) => slow_reader_latency.push(d),
            Event::Disconnected => disconnects += 1,
        }
    }

    for h in handles {
        let _ = h.await;
    }

    let actual_duration_secs = start.elapsed().as_secs_f64();
    let command_report = LatencyReport::from_samples(&command_latency);
    let e1_1_pass = command_report
        .as_ref()
        .map(|r| r.p99_ms < args.sla_p99_ms)
        .unwrap_or(false);

    let mut notes = Vec::new();
    if login_failures > 0 {
        notes.push(format!("{login_failures} bot(s) failed to log in"));
    }
    if disconnects > 0 {
        notes.push(format!(
            "{disconnects} disconnect(s) observed (expected for the slow-reader cohort)"
        ));
    }

    let server_metrics = if let Some(url) = &args.metrics_url {
        match metrics_scrape::scrape(url).await {
            Ok(text) => Some(text),
            Err(e) => {
                notes.push(format!("failed to scrape --metrics-url {url}: {e}"));
                None
            }
        }
    } else {
        None
    };

    let report = RunReport {
        players: args.players,
        slow_reader_fraction: args.slow_reader_fraction,
        requested_duration_secs: args.duration_secs,
        actual_duration_secs,
        login_failures,
        disconnects,
        commands_sent: command_latency.len(),
        sla_p99_ms: args.sla_p99_ms,
        command_latency: command_report.clone(),
        slow_reader_command_latency: LatencyReport::from_samples(&slow_reader_latency),
        login_latency: LatencyReport::from_samples(&login_latency),
        e1_1_pass,
        notes,
        server_metrics,
    };

    if let Some(parent) = args.out_prefix.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json_path = args.out_prefix.with_extension("json");
    let md_path = args.out_prefix.with_extension("md");
    std::fs::write(
        &json_path,
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(&md_path, report.to_markdown()).map_err(|e| e.to_string())?;

    println!("{}", report.to_markdown());
    println!("wrote {} and {}", json_path.display(), md_path.display());

    if args.fail_on_sla_miss && !e1_1_pass {
        return Err(format!(
            "p99 did not meet the {:.0} ms SLA",
            args.sla_p99_ms
        ));
    }
    Ok(())
}
