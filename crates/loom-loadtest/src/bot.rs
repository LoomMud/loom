// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! One bot's lifecycle: login (per `warp/loadbot/README.md`'s contract),
//! then repeatedly run mix entries until the run's deadline, reporting
//! timed events to the collector.

use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use rand::rngs::StdRng;
use regex::Regex;
use tokio::sync::{RwLock, mpsc};
use tokio::time::Instant;

use crate::mix::{Mix, render_step};
use crate::session::{Session, SessionError};

pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(5);
pub const LOGIN_STEP_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug)]
pub enum Event {
    /// A bot reached the prompt after its name. `at_ms` is the offset from
    /// the run start that the login attempt began at.
    LoginOk {
        latency: Duration,
        at_ms: u64,
        /// Time spent in the name/password exchange before the world's own
        /// prompts -- the Argon2id + `login_start` part of the path, which
        /// the account service answers without touching the world thread.
        auth_ms: u64,
    },
    LoginFailed(String),
    /// A normal-cohort command round trip, timed from just before the send
    /// to the prompt. A prompt timeout is deliberately not recorded as a
    /// sample: the E1.1 p99 stays honest to what actually completed.
    ///
    /// `at_ms` is the send offset from the run start (OBI-344). Without it
    /// the distribution has no time axis and a tail has no explanation.
    Command {
        latency: Duration,
        at_ms: u64,
    },
    /// One command from the slow-reader cohort; kept separate so the
    /// artificial read delay doesn't contaminate the real SLA number.
    SlowReaderCommand {
        latency: Duration,
        at_ms: u64,
    },
    /// A bot lost its connection mid-run (backpressure drop, disconnect).
    Disconnected,
    /// Self-measured scheduling lag of the bot's own runtime: one mix entry
    /// ended `lag` later than the pause it asked for. This is the bot side of
    /// the OBI-344 attribution -- if the loadtest process is starved, its
    /// latency numbers are inflated by its own scheduler, not by the driver.
    /// Recorded at the end of a pause, so `at_ms` is when the lag was
    /// observed.
    BotLag {
        at_ms: u64,
        lag: Duration,
    },
    /// A command never reached the prompt inside `PROMPT_TIMEOUT`, so it was
    /// dropped from the latency distribution. Without this counter the gate
    /// would silently treat "the server never answered" as "no sample", which
    /// hides exactly the worst tail (OBI-344).
    PromptTimeout {
        at_ms: u64,
        slow_reader: bool,
    },
}

pub struct BotConfig {
    pub addr: String,
    pub name: String,
    pub password: String,
    pub class: String,
    pub slow_reader: bool,
    pub slow_reader_delay: Duration,
    pub think_min: Duration,
    pub think_max: Duration,
    /// Absolute instant at which this bot stops sending commands and quits.
    /// Computed once by the caller so all bots end together.
    pub run_until: Instant,
    /// When the whole run started. Every sample is stamped with its offset
    /// from this anchor, which is what lets the report line the latency tail
    /// up against the server's counter series and the scraper's own clock
    /// (OBI-344). One `Instant` is shared by the bots, the metrics scraper
    /// and the timer-lag probe, so their timelines are comparable by
    /// construction rather than by wall-clock guessing.
    pub run_start: Instant,
}

/// Regex for one of the three post-password prompts (README table).
fn post_password_re() -> Regex {
    Regex::new(r"Create a new character|You take over your body again|Choose a class").unwrap()
}

fn prompt_re() -> Regex {
    Regex::new(r"<\d+/\d+hp> ").unwrap()
}

fn failure_re() -> Regex {
    Regex::new(
        r"already playing|That name was just taken|Too many failed attempts|The account service is unavailable",
    )
    .unwrap()
}

/// The boundary between the two halves of a login, measured as the elapsed
/// time to the prompt the *world* prints after the password (OBI-344). That
/// first half is the account service -- Argon2id verify/enrol plus
/// `login_start` -- which runs off the world thread; whatever comes after it
/// is the world thread creating or loading the character. A run whose logins
/// are slow in the first half is heating the auth pool; one slow in the
/// second half is stalling the world loop, and the fix is not the same.
pub type AuthPhase = u64;

/// Logs `session` in per the R4 contract: name, password, then handle
/// character creation / class choice / reconnection, ending at the first
/// `<hp> ` prompt. On a recognized failure prompt, returns
/// `SessionError`-wrapped text via `Event::LoginFailed` (caller decides
/// whether to retry). Ok(_) is the `AuthPhase` split point.
async fn login(session: &mut Session, cfg: &BotConfig) -> Result<AuthPhase, String> {
    let t0 = Instant::now();
    session
        .expect(&Regex::new("By what name").unwrap(), LOGIN_STEP_TIMEOUT)
        .await
        .map_err(|e| e.to_string())?;
    session
        .send_line(&cfg.name)
        .await
        .map_err(|e| e.to_string())?;

    session
        .expect(&Regex::new("Password: ").unwrap(), LOGIN_STEP_TIMEOUT)
        .await
        .map_err(|e| e.to_string())?;
    session
        .send_line(&cfg.password)
        .await
        .map_err(|e| e.to_string())?;

    let combined = {
        let mut pattern = post_password_re().as_str().to_string();
        pattern.push('|');
        pattern.push_str(failure_re().as_str());
        Regex::new(&pattern).unwrap()
    };
    let matched = session
        .expect(&combined, LOGIN_STEP_TIMEOUT)
        .await
        .map_err(|e| e.to_string())?;
    // Everything up to here is answered before the world thread gets the
    // character; split the measurement at this prompt.
    let auth_ms = t0.elapsed().as_millis() as u64;

    if failure_re().is_match(&matched) {
        return Err(matched);
    }

    if matched.starts_with("Create") {
        session.send_line("yes").await.map_err(|e| e.to_string())?;
        session
            .expect(
                &Regex::new("Choose a password").unwrap(),
                LOGIN_STEP_TIMEOUT,
            )
            .await
            .map_err(|e| e.to_string())?;
        session
            .send_line(&cfg.password)
            .await
            .map_err(|e| e.to_string())?;
        session
            .expect(&Regex::new("Confirm password").unwrap(), LOGIN_STEP_TIMEOUT)
            .await
            .map_err(|e| e.to_string())?;
        session
            .send_line(&cfg.password)
            .await
            .map_err(|e| e.to_string())?;
        let m2 = session
            .expect(
                &Regex::new(&format!("{}|{}", "Choose a class", failure_re().as_str())).unwrap(),
                LOGIN_STEP_TIMEOUT,
            )
            .await
            .map_err(|e| e.to_string())?;
        if failure_re().is_match(&m2) {
            return Err(m2);
        }
        session
            .send_line(&cfg.class)
            .await
            .map_err(|e| e.to_string())?;
    } else if matched.starts_with("Choose a class") {
        session
            .send_line(&cfg.class)
            .await
            .map_err(|e| e.to_string())?;
    }
    // "You take over your body again": nothing more to send.

    session
        .expect(&prompt_re(), LOGIN_STEP_TIMEOUT)
        .await
        .map_err(|e| e.to_string())?;
    Ok(auth_ms)
}

/// Runs one bot end to end: connect, login, then mix entries until
/// `cfg.run_until`, reporting every event to `events`.
#[allow(clippy::too_many_arguments)]
pub async fn run_bot(
    cfg: BotConfig,
    mix: Arc<Mix>,
    peers: Arc<RwLock<Vec<String>>>,
    mut rng: StdRng,
    events: mpsc::Sender<Event>,
) {
    let mut session = match Session::connect(&cfg.addr, &cfg.name).await {
        Ok(s) => s,
        Err(e) => {
            let _ = events
                .send(Event::LoginFailed(format!("connect: {e}")))
                .await;
            return;
        }
    };

    let login_start = Instant::now();
    let login_at_ms = login_start.duration_since(cfg.run_start).as_millis() as u64;
    let auth_ms = match login(&mut session, &cfg).await {
        Ok(p) => p,
        Err(reason) => {
            let _ = events.send(Event::LoginFailed(reason)).await;
            session.close().await;
            return;
        }
    };
    let _ = events
        .send(Event::LoginOk {
            latency: login_start.elapsed(),
            at_ms: login_at_ms,
            auth_ms,
        })
        .await;

    {
        let mut w = peers.write().await;
        w.push(cfg.name.clone());
    }

    if cfg.slow_reader {
        session.read_delay = Some(cfg.slow_reader_delay);
    }

    let prompt = prompt_re();
    'run: while Instant::now() < cfg.run_until {
        let entry = mix.pick(&mut rng).clone();
        for step in &entry.steps {
            let peer = {
                let r = peers.read().await;
                r.iter()
                    .filter(|p| *p != &cfg.name)
                    .nth(rng.gen_range(0..r.len().max(1)))
                    .cloned()
                    .unwrap_or_else(|| cfg.name.clone())
            };
            let line = render_step(step, &peer, &mut rng);
            let t0 = Instant::now();
            let at_ms = t0.duration_since(cfg.run_start).as_millis() as u64;
            if session.send_line(&line).await.is_err() {
                let _ = events.send(Event::Disconnected).await;
                break 'run;
            }
            match session.expect(&prompt, PROMPT_TIMEOUT).await {
                Ok(_) => {
                    let elapsed = t0.elapsed();
                    let ev = if cfg.slow_reader {
                        Event::SlowReaderCommand {
                            latency: elapsed,
                            at_ms,
                        }
                    } else {
                        Event::Command {
                            latency: elapsed,
                            at_ms,
                        }
                    };
                    let _ = events.send(ev).await;
                }
                Err(SessionError::Disconnected) => {
                    let _ = events.send(Event::Disconnected).await;
                    break 'run;
                }
                Err(_) => {
                    // Timeout: not recorded as a latency sample -- the p99
                    // stays honest to what actually completed -- but counted,
                    // so a run that stopped answering is visible.
                    let _ = events
                        .send(Event::PromptTimeout {
                            at_ms,
                            slow_reader: cfg.slow_reader,
                        })
                        .await;
                    continue 'run;
                }
            }
        }
        let think = Duration::from_millis(rng.gen_range(
            cfg.think_min.as_millis() as u64
                ..=cfg.think_max.as_millis().max(cfg.think_min.as_millis() + 1) as u64,
        ));
        let think_for = think.min(cfg.run_until.saturating_duration_since(Instant::now()));
        let pause_start = Instant::now();
        tokio::time::sleep(think_for).await;
        // Overshoot of a pause we asked the runtime for is direct evidence
        // about this process's own scheduling, which is the one confounder a
        // latency gate cannot leave unmeasured (OBI-344).
        let overshoot = pause_start.elapsed().saturating_sub(think_for);
        if !overshoot.is_zero() {
            let _ = events
                .send(Event::BotLag {
                    at_ms: Instant::now().duration_since(cfg.run_start).as_millis() as u64,
                    lag: overshoot,
                })
                .await;
        }
    }

    let _ = session.send_line("quit").await;
    session.close().await;
}
