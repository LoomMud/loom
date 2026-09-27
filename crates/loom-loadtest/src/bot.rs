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
    LoginOk(Duration),
    LoginFailed(String),
    Command(Duration),
    SlowReaderCommand(Duration),
    Disconnected,
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
    pub run_until: Instant,
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

/// Logs `session` in per the R4 contract: name, password, then handle
/// character creation / class choice / reconnection, ending at the first
/// `<hp> ` prompt. On a recognized failure prompt, returns
/// `SessionError`-wrapped text via `Event::LoginFailed` (caller decides
/// whether to retry).
async fn login(session: &mut Session, cfg: &BotConfig) -> Result<(), String> {
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
    Ok(())
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
    if let Err(reason) = login(&mut session, &cfg).await {
        let _ = events.send(Event::LoginFailed(reason)).await;
        session.close().await;
        return;
    }
    let _ = events.send(Event::LoginOk(login_start.elapsed())).await;

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
            if session.send_line(&line).await.is_err() {
                let _ = events.send(Event::Disconnected).await;
                break 'run;
            }
            match session.expect(&prompt, PROMPT_TIMEOUT).await {
                Ok(_) => {
                    let elapsed = t0.elapsed();
                    let ev = if cfg.slow_reader {
                        Event::SlowReaderCommand(elapsed)
                    } else {
                        Event::Command(elapsed)
                    };
                    let _ = events.send(ev).await;
                }
                Err(SessionError::Disconnected) => {
                    let _ = events.send(Event::Disconnected).await;
                    break 'run;
                }
                Err(_) => {
                    // Timeout: count nothing, keep going with the next
                    // entry rather than wedging this bot forever.
                    continue 'run;
                }
            }
        }
        let think = Duration::from_millis(rng.gen_range(
            cfg.think_min.as_millis() as u64
                ..=cfg.think_max.as_millis().max(cfg.think_min.as_millis() + 1) as u64,
        ));
        tokio::time::sleep(think.min(cfg.run_until.saturating_duration_since(Instant::now())))
            .await;
    }

    let _ = session.send_line("quit").await;
    session.close().await;
}
