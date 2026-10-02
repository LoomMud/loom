// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `POST /api/v1/hooks/github` (OBI-212, D-B3.12, threat model M-GH-6):
//! the GitHub webhook that kicks `GitWorker`'s `SyncMain` loop
//! (OBI-190). This is a player-origin route (M-X-1) -- GitHub never
//! needs the staff host.
//!
//! The payload is only a trigger (M-GH-6): the driver `git fetch`es
//! `main` itself and never applies anything the payload claims, so a
//! forged-but-signed or replayed hook can at worst cause a no-op fetch.
//!
//! Order of checks, cheapest/safest first:
//! 1. Body size (axum's `DefaultBodyLimit` on this route, 1 MiB --
//!    `413` before any handler code runs at all).
//! 2. Endpoint rate limit (30/min, a single bucket -- this is one
//!    webhook URL, not per-caller) so a flood can't buy extra HMAC
//!    compute.
//! 3. `X-Hub-Signature-256` HMAC-SHA256 over the raw body, constant-time
//!    (`hmac::Mac::verify_slice`, same primitive as the JWT signer).
//! 4. `X-GitHub-Delivery` dedupe (LRU of the last 1000 ids) -- a replayed
//!    delivery id is ignored even if it would otherwise match.
//! 5. Event dispatch: `ping` (any payload) and `push` to the configured
//!    repo id + `refs/heads/main` are accepted (`202`); everything else
//!    is a no-op (`200`). An accepted `push` debounces into a single
//!    coalesced [`GithubWebhookKicker::kick`] call even under a burst of
//!    deliveries.

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Bytes;
use axum::extract::DefaultBodyLimit;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::Sha256;

use crate::HttpState;

type HmacSha256 = Hmac<Sha256>;

/// 1 MiB (D-B3.12/M-GH-6).
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// 30/min (D-B3.12). A single bucket for the whole endpoint, not
/// per-caller -- GitHub's webhook deliveries all come from its own
/// address ranges, so a per-IP bucket would just be a per-GitHub
/// bucket.
const RATE_LIMIT_CAPACITY: f64 = 30.0;
const RATE_LIMIT_REFILL_INTERVAL: Duration = Duration::from_secs(2); // 30/min

/// Last 1000 `X-GitHub-Delivery` ids (D-B3.12).
const DELIVERY_LRU_CAPACITY: usize = 1000;

/// Coalescing window for [`GithubWebhookKicker::kick`]: a burst of
/// accepted `push` deliveries inside this window collapses into exactly
/// one kick, fired at the end of the window (trailing debounce).
const DEFAULT_KICK_DEBOUNCE: Duration = Duration::from_secs(2);

/// Wakes the sync loop (D-B3.7). Implemented for `loom_git::GitWorkerHandle`
/// in production; tests use a counting mock.
pub trait GithubWebhookKicker: Send + Sync {
    fn kick(&self);
}

impl GithubWebhookKicker for loom_git::GitWorkerHandle {
    fn kick(&self) {
        loom_git::GitWorkerHandle::kick(self);
    }
}

/// Trailing debounce around a [`GithubWebhookKicker`]: repeated
/// [`DebouncedKicker::mark`] calls inside one window collapse into a
/// single `kick()` call, fired once the window elapses with no (new)
/// marks resetting it mid-flight -- a burst of webhook deliveries never
/// queues more than one pending sync kick.
struct DebouncedKicker {
    dirty: AtomicBool,
    kicker: Arc<dyn GithubWebhookKicker>,
}

impl DebouncedKicker {
    fn spawn(kicker: Arc<dyn GithubWebhookKicker>, interval: Duration) -> Arc<Self> {
        let this = Arc::new(Self {
            dirty: AtomicBool::new(false),
            kicker,
        });
        let bg = this.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                if bg.dirty.swap(false, Ordering::SeqCst) {
                    bg.kicker.kick();
                }
            }
        });
        this
    }

    fn mark(&self) {
        self.dirty.store(true, Ordering::SeqCst);
    }
}

/// Bounded FIFO of recently-seen `X-GitHub-Delivery` ids (D-B3.12: "an
/// LRU of the last 1000"). Insertion order eviction is enough here --
/// there's no "touch to refresh recency" requirement, just "don't
/// process the same delivery twice".
struct DeliveryLru {
    seen: HashSet<String>,
    order: VecDeque<String>,
    capacity: usize,
}

impl DeliveryLru {
    fn new(capacity: usize) -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    /// Returns `true` if `id` was already seen (a duplicate delivery);
    /// otherwise records it and returns `false`.
    fn check_and_insert(&mut self, id: &str) -> bool {
        if self.seen.contains(id) {
            return true;
        }
        if self.order.len() >= self.capacity
            && let Some(oldest) = self.order.pop_front()
        {
            self.seen.remove(&oldest);
        }
        self.seen.insert(id.to_string());
        self.order.push_back(id.to_string());
        false
    }
}

/// A single-bucket token limiter: no per-caller key, one shared budget
/// for the whole endpoint (D-B3.12: "Endpoint rate limit: 30/min").
struct EndpointRateLimiter {
    tokens: f64,
    last_refill: Instant,
    capacity: f64,
    refill_interval: Duration,
}

impl EndpointRateLimiter {
    fn new(capacity: f64, refill_interval: Duration) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
            capacity,
            refill_interval,
        }
    }

    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last_refill);
        let refill_steps = elapsed.as_secs_f64() / self.refill_interval.as_secs_f64();
        if refill_steps > 0.0 {
            self.tokens = (self.tokens + refill_steps).min(self.capacity);
            self.last_refill = now;
        }
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Config + wiring for the GitHub webhook route. Built once at startup
/// (`HttpState::with_github_webhook`); the HMAC secret is read once from
/// the mounted secret file and kept in memory only (same convention as
/// `loom_git::github::GitHubAppClient::from_pem_file`).
#[derive(Clone)]
pub struct GithubWebhookConfig {
    secret: Arc<Vec<u8>>,
    repo_id: u64,
    kicker: Arc<DebouncedKicker>,
    seen: Arc<Mutex<DeliveryLru>>,
    rate: Arc<Mutex<EndpointRateLimiter>>,
}

impl GithubWebhookConfig {
    /// Reads the webhook secret from `secret_path` (e.g.
    /// `/run/secrets/warp_webhook`) once; `repo_id` is the configured
    /// GitHub numeric repository id -- `push` is only accepted for this
    /// repo and `refs/heads/main` (everything else is a no-op).
    pub fn from_secret_file(
        secret_path: &std::path::Path,
        repo_id: u64,
        kicker: Arc<dyn GithubWebhookKicker>,
    ) -> std::io::Result<Self> {
        let raw = std::fs::read(secret_path)?;
        Ok(Self::new(raw, repo_id, kicker))
    }

    pub fn new(secret: Vec<u8>, repo_id: u64, kicker: Arc<dyn GithubWebhookKicker>) -> Self {
        // Trailing newline on a mounted secret file is common and not
        // part of the secret.
        let trimmed = trim_trailing_newline(secret);
        Self {
            secret: Arc::new(trimmed),
            repo_id,
            kicker: DebouncedKicker::spawn(kicker, DEFAULT_KICK_DEBOUNCE),
            seen: Arc::new(Mutex::new(DeliveryLru::new(DELIVERY_LRU_CAPACITY))),
            rate: Arc::new(Mutex::new(EndpointRateLimiter::new(
                RATE_LIMIT_CAPACITY,
                RATE_LIMIT_REFILL_INTERVAL,
            ))),
        }
    }

    /// Test-only seam: a shorter debounce window so coalescing tests
    /// don't need multi-second real-time sleeps (paired with
    /// `tokio::time::pause`).
    #[cfg(test)]
    pub fn new_with_debounce(
        secret: Vec<u8>,
        repo_id: u64,
        kicker: Arc<dyn GithubWebhookKicker>,
        debounce: Duration,
    ) -> Self {
        let trimmed = trim_trailing_newline(secret);
        Self {
            secret: Arc::new(trimmed),
            repo_id,
            kicker: DebouncedKicker::spawn(kicker, debounce),
            seen: Arc::new(Mutex::new(DeliveryLru::new(DELIVERY_LRU_CAPACITY))),
            rate: Arc::new(Mutex::new(EndpointRateLimiter::new(
                RATE_LIMIT_CAPACITY,
                RATE_LIMIT_REFILL_INTERVAL,
            ))),
        }
    }
}

fn trim_trailing_newline(mut secret: Vec<u8>) -> Vec<u8> {
    while matches!(secret.last(), Some(b'\n') | Some(b'\r')) {
        secret.pop();
    }
    secret
}

pub fn webhook_router() -> Router<HttpState> {
    Router::new()
        .route("/api/v1/hooks/github", post(github_webhook))
        .route_layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

#[derive(Debug, Deserialize)]
struct PushPayload {
    #[serde(rename = "ref")]
    git_ref: String,
    repository: PushRepository,
}

#[derive(Debug, Deserialize)]
struct PushRepository {
    id: u64,
}

const MAIN_REF: &str = "refs/heads/main";

async fn github_webhook(
    State(state): State<HttpState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let Some(config) = state.github_webhook.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };

    // Rate limit before any HMAC compute -- a flood shouldn't get to
    // spend our CPU on signature verification either.
    if !config
        .rate
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .try_consume()
    {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    if !verify_signature(&config.secret, &headers, &body) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // Dedupe: a delivery id we've already processed is ignored
    // regardless of what it claims, same response as any other no-op
    // event.
    if let Some(delivery_id) = headers
        .get("X-GitHub-Delivery")
        .and_then(|v| v.to_str().ok())
    {
        let duplicate = config
            .seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .check_and_insert(delivery_id);
        if duplicate {
            return StatusCode::OK.into_response();
        }
    }

    let event = headers
        .get("X-GitHub-Event")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    match event {
        "ping" => StatusCode::ACCEPTED.into_response(),
        "push" => match serde_json::from_slice::<PushPayload>(&body) {
            Ok(payload)
                if payload.repository.id == config.repo_id && payload.git_ref == MAIN_REF =>
            {
                config.kicker.mark();
                StatusCode::ACCEPTED.into_response()
            }
            Ok(_) => StatusCode::OK.into_response(),
            Err(e) => {
                tracing::warn!(error = %e, "loom-http: unparseable `push` webhook payload, ignoring");
                StatusCode::OK.into_response()
            }
        },
        _ => StatusCode::OK.into_response(),
    }
}

/// Constant-time HMAC-SHA256 verification of `X-Hub-Signature-256:
/// sha256=<hex>` over the raw body (D-B3.12/M-GH-6). Any malformed
/// header (missing, no `sha256=` prefix, bad hex) is just a verification
/// failure -- never a panic or a different status code than a bad MAC.
fn verify_signature(secret: &[u8], headers: &HeaderMap, body: &[u8]) -> bool {
    let Some(header) = headers
        .get("X-Hub-Signature-256")
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Some(hex_sig) = header.strip_prefix("sha256=") else {
        return false;
    };
    let Some(sig) = decode_hex(hex_sig) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&sig).is_ok()
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use std::sync::atomic::AtomicUsize;
    use tower::ServiceExt;

    use crate::HttpState;
    use loom_obs::{PrometheusMetrics, Readiness};
    use tokio::sync::mpsc;

    struct MockKicker {
        count: Arc<AtomicUsize>,
    }

    impl GithubWebhookKicker for MockKicker {
        fn kick(&self) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    const SECRET: &[u8] = b"test-secret";
    const REPO_ID: u64 = 42;

    fn sign(body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(SECRET).unwrap();
        mac.update(body);
        let bytes = mac.finalize().into_bytes();
        format!(
            "sha256={}",
            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
        )
    }

    fn push_body(repo_id: u64, git_ref: &str) -> Vec<u8> {
        serde_json::json!({
            "ref": git_ref,
            "repository": { "id": repo_id },
        })
        .to_string()
        .into_bytes()
    }

    fn test_app(kicker: Arc<MockKicker>, debounce: Duration) -> Router {
        let (ws_accept_tx, _ws_accept_rx) = mpsc::channel(16);
        let config =
            GithubWebhookConfig::new_with_debounce(SECRET.to_vec(), REPO_ID, kicker, debounce);
        let state = HttpState::new(
            ws_accept_tx,
            Readiness::new(),
            PrometheusMetrics::new_unregistered(),
        )
        .with_github_webhook(config);
        crate::app(state)
    }

    fn request(body: Vec<u8>, delivery: &str, event: &str, bad_sig: bool) -> Request<Body> {
        let sig = if bad_sig {
            "sha256=0000000000000000000000000000000000000000000000000000000000000000".to_string()
        } else {
            sign(&body)
        };
        Request::builder()
            .method("POST")
            .uri("/api/v1/hooks/github")
            .header("X-Hub-Signature-256", sig)
            .header("X-GitHub-Delivery", delivery)
            .header("X-GitHub-Event", event)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    #[tokio::test]
    async fn bad_hmac_is_401() {
        let app = test_app(
            Arc::new(MockKicker {
                count: Arc::new(AtomicUsize::new(0)),
            }),
            Duration::from_millis(10),
        );
        let body = push_body(REPO_ID, MAIN_REF);
        let req = request(body, "d1", "push", true);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn good_hmac_ping_is_202() {
        let app = test_app(
            Arc::new(MockKicker {
                count: Arc::new(AtomicUsize::new(0)),
            }),
            Duration::from_millis(10),
        );
        let req = request(b"{}".to_vec(), "d1", "ping", false);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn push_on_configured_ref_is_202_and_coalesces_a_burst_into_one_kick() {
        let count = Arc::new(AtomicUsize::new(0));
        let kicker = Arc::new(MockKicker {
            count: count.clone(),
        });
        // Real (short) debounce window -- a burst of deliveries all land
        // well inside it, then we wait past it once and check the
        // kicker only fired once.
        let debounce = Duration::from_millis(150);
        let app = test_app(kicker, debounce);

        for i in 0..5 {
            let body = push_body(REPO_ID, MAIN_REF);
            let req = request(body, &format!("delivery-{i}"), "push", false);
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::ACCEPTED);
        }
        // Still inside the debounce window: no kick has fired yet.
        assert_eq!(count.load(Ordering::SeqCst), 0);

        tokio::time::sleep(debounce + Duration::from_millis(100)).await;

        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn wrong_ref_is_ignored_200_no_kick() {
        let count = Arc::new(AtomicUsize::new(0));
        let kicker = Arc::new(MockKicker {
            count: count.clone(),
        });
        let app = test_app(kicker, Duration::from_millis(10));
        let body = push_body(REPO_ID, "refs/heads/feature");
        let req = request(body, "d1", "push", false);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn wrong_repo_is_ignored_200_no_kick() {
        let count = Arc::new(AtomicUsize::new(0));
        let kicker = Arc::new(MockKicker {
            count: count.clone(),
        });
        let app = test_app(kicker, Duration::from_millis(10));
        let body = push_body(REPO_ID + 1, MAIN_REF);
        let req = request(body, "d1", "push", false);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn other_event_is_ignored_200() {
        let app = test_app(
            Arc::new(MockKicker {
                count: Arc::new(AtomicUsize::new(0)),
            }),
            Duration::from_millis(10),
        );
        let req = request(b"{}".to_vec(), "d1", "pull_request", false);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn duplicate_delivery_id_is_ignored() {
        let count = Arc::new(AtomicUsize::new(0));
        let kicker = Arc::new(MockKicker {
            count: count.clone(),
        });
        let app = test_app(kicker, Duration::from_millis(10));
        let body = push_body(REPO_ID, MAIN_REF);

        let req = request(body.clone(), "dup-1", "push", false);
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // Same delivery id again: ignored even though the payload would
        // otherwise be accepted.
        let req = request(body, "dup-1", "push", false);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn oversized_body_is_413() {
        let app = test_app(
            Arc::new(MockKicker {
                count: Arc::new(AtomicUsize::new(0)),
            }),
            Duration::from_millis(10),
        );
        let big = vec![b'a'; MAX_BODY_BYTES + 1];
        let req = request(big, "d1", "push", false);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn rate_limit_tripped_is_429() {
        let config = GithubWebhookConfig::new_with_debounce(
            SECRET.to_vec(),
            REPO_ID,
            Arc::new(MockKicker {
                count: Arc::new(AtomicUsize::new(0)),
            }),
            Duration::from_millis(10),
        );
        // Drain the bucket directly rather than firing 31 real requests.
        {
            let mut rate = config.rate.lock().unwrap();
            for _ in 0..(RATE_LIMIT_CAPACITY as usize) {
                assert!(rate.try_consume());
            }
            assert!(!rate.try_consume());
        }
        let (ws_accept_tx, _ws_accept_rx) = mpsc::channel(16);
        let state = HttpState::new(
            ws_accept_tx,
            Readiness::new(),
            PrometheusMetrics::new_unregistered(),
        )
        .with_github_webhook(config);
        let app = crate::app(state);

        let req = request(b"{}".to_vec(), "d1", "ping", false);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn delivery_lru_evicts_oldest_past_capacity() {
        let mut lru = DeliveryLru::new(2);
        assert!(!lru.check_and_insert("a"));
        assert!(!lru.check_and_insert("b"));
        assert!(!lru.check_and_insert("c")); // evicts "a"
        assert!(!lru.check_and_insert("a")); // "a" was evicted, not a dup
        assert!(lru.check_and_insert("c")); // still present
    }

    #[test]
    fn decode_hex_rejects_odd_length_and_bad_chars() {
        assert!(decode_hex("abc").is_none());
        assert!(decode_hex("zz").is_none());
        assert_eq!(decode_hex("ff"), Some(vec![0xff]));
    }
}
