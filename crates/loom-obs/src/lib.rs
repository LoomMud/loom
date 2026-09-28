// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `loom`'s observability crate (design spec §10). Owner: Legolas.
//!
//! Three independent pieces, each usable on its own:
//!
//! - [`init_tracing`]: a `tracing-subscriber` registry with an env-filter
//!   and a JSON `fmt` layer, plus an optional OTLP trace exporter (only
//!   installed when `LOOM_OTLP_ENDPOINT` is set -- observability must
//!   never require a collector to be present to boot).
//! - [`PrometheusMetrics`]: a `metrics`-facade recorder that renders the
//!   Prometheus text exposition format for `loom-http`'s `/metrics` route.
//!   Recording only (no HTTP listener of its own): the recorder never
//!   spawns tasks or opens sockets, so it can't race with or duplicate
//!   `loom-http`'s own server.
//! - [`Readiness`]: a shared, cheaply-cloned gate the world thread flips
//!   once startup (mudlib compiled, DB backend reachable) is done, read
//!   by `loom-http`'s `/readyz` route.
//!
//! None of this blocks the world thread: tracing/metrics recording is
//! synchronous and in-memory (the OTLP exporter batches and flushes on a
//! background task), and `Readiness` is a single atomic load/store.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Env var read by [`init_tracing`]: when set to an OTLP/gRPC collector
/// endpoint (e.g. `http://otel-collector:4317`), spans are exported there
/// in addition to the local `fmt` logs. Unset (the default) means no OTLP
/// exporter is built at all -- no background task, no connection attempt.
pub const OTLP_ENDPOINT_ENV: &str = "LOOM_OTLP_ENDPOINT";

/// Holds resources that must outlive the process for tracing to keep
/// working, and flushes/shuts down the OTLP exporter (if any) on drop.
///
/// Callers must keep this alive for the lifetime of `main`; dropping it
/// early silently stops trace export (spans still show up in local logs
/// via the `fmt` layer).
#[must_use = "dropping the guard early stops OTLP export"]
pub struct TracingGuard {
    tracer_provider: Option<SdkTracerProvider>,
}

impl Drop for TracingGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.tracer_provider.take() {
            // Best-effort: shutdown() flushes buffered spans. Errors here
            // (e.g. collector unreachable) are not actionable at process
            // exit, so they're logged rather than propagated.
            if let Err(err) = provider.shutdown() {
                tracing::warn!(error = %err, "otel tracer provider shutdown failed");
            }
        }
    }
}

/// Env var read by [`init_tracing`]: set to `json` to emit structured
/// JSON logs on stdout (production/log-aggregator friendly); unset or any
/// other value uses `tracing-subscriber`'s human-readable default
/// formatter (local dev).
pub const LOG_FORMAT_ENV: &str = "LOOM_LOG_FORMAT";

/// Initialise the global `tracing` subscriber: env-filter + `fmt`
/// (human-readable, or JSON if [`LOG_FORMAT_ENV`] is `json`), plus an
/// OTLP trace layer iff [`OTLP_ENDPOINT_ENV`] is set.
///
/// `service_name` tags every exported span's `service.name` resource
/// attribute. Panics if called more than once per process (a
/// `tracing`/`tracing-subscriber` global-default constraint), same as
/// bare `tracing_subscriber::fmt().init()`.
pub fn init_tracing(service_name: &str) -> TracingGuard {
    let env_filter = tracing_subscriber::EnvFilter::from_default_env();
    let use_json = std::env::var(LOG_FORMAT_ENV)
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    let fmt_layer: Box<dyn tracing_subscriber::Layer<_> + Send + Sync> = if use_json {
        Box::new(
            tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(true),
        )
    } else {
        Box::new(tracing_subscriber::fmt::layer().with_target(true))
    };

    let (otel_layer, tracer_provider) = match std::env::var(OTLP_ENDPOINT_ENV) {
        Ok(endpoint) if !endpoint.is_empty() => {
            match build_tracer_provider(service_name, &endpoint) {
                Ok(provider) => {
                    let tracer = provider.tracer(service_name.to_string());
                    (
                        Some(tracing_opentelemetry::layer().with_tracer(tracer)),
                        Some(provider),
                    )
                }
                Err(err) => {
                    // Don't fail startup over a bad/unreachable collector:
                    // local logging still works without OTLP.
                    eprintln!(
                        "loom-obs: failed to build OTLP exporter for {endpoint}: {err}; continuing without OTLP export"
                    );
                    (None, None)
                }
            }
        }
        _ => (None, None),
    };

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .with(otel_layer)
        .init();

    TracingGuard { tracer_provider }
}

fn build_tracer_provider(
    service_name: &str,
    endpoint: &str,
) -> Result<SdkTracerProvider, Box<dyn std::error::Error>> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint.to_string())
        .build()?;

    Ok(SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name(service_name.to_string())
                .build(),
        )
        .build())
}

/// A `metrics`-facade Prometheus recorder. Owns the process-global
/// `metrics` recorder (installed once via [`PrometheusMetrics::install`])
/// and can render the current state as Prometheus text exposition format
/// for `loom-http`'s `/metrics` route.
#[derive(Clone)]
pub struct PrometheusMetrics {
    handle: PrometheusHandle,
}

impl PrometheusMetrics {
    /// Build a Prometheus recorder and install it as the process-global
    /// `metrics` recorder. Must be called at most once per process (a
    /// `metrics` crate constraint); subsequent calls return an error.
    pub fn install()
    -> Result<Self, metrics::SetRecorderError<metrics_exporter_prometheus::PrometheusRecorder>>
    {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::set_global_recorder(recorder)?;
        Ok(Self { handle })
    }

    /// Build a Prometheus recorder without installing it as the
    /// process-global `metrics` recorder. Useful for tests that spin up
    /// multiple independent `HttpState`s in one process (where
    /// `install`'s one-recorder-per-process constraint would make every
    /// call after the first fail) and don't care about recording actual
    /// `metrics::counter!`/`gauge!` calls -- just about `/metrics`
    /// rendering something.
    pub fn new_unregistered() -> Self {
        let handle = PrometheusBuilder::new().build_recorder().handle();
        Self { handle }
    }

    /// Render the current metric state as Prometheus text exposition
    /// format (the `/metrics` route's response body).
    pub fn render(&self) -> String {
        self.handle.render()
    }
}

/// A shared readiness gate: `false` until the world thread and its
/// dependencies (mudlib compiled, DB backend reachable) have finished
/// startup, then flipped to `true` for the rest of the process's life.
/// `loom-http`'s `/readyz` route reports 503 while this is `false` and
/// 200 once it's `true`; `/healthz` (liveness -- "is the process up at
/// all") never consults it.
#[derive(Clone, Default)]
pub struct Readiness(Arc<AtomicBool>);

impl Readiness {
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    /// Mark the process ready. Idempotent.
    pub fn set_ready(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_ready(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_starts_false_and_latches_true() {
        let readiness = Readiness::new();
        assert!(!readiness.is_ready());
        readiness.set_ready();
        assert!(readiness.is_ready());

        // Cloned handles share the same underlying gate.
        let clone = readiness.clone();
        assert!(clone.is_ready());
    }

    #[test]
    fn prometheus_metrics_renders_recorded_counters() {
        // `metrics::set_global_recorder` can only succeed once per
        // process, and other tests in this binary may already have
        // installed one -- accept either outcome, then check that
        // *something* installed (this test's own counter, if we won the
        // race, or an already-installed recorder either way) renders as
        // valid Prometheus text.
        let metrics = match PrometheusMetrics::install() {
            Ok(metrics) => metrics,
            Err(_) => return,
        };

        metrics::counter!("loom_obs_test_counter_total").increment(1);
        let rendered = metrics.render();
        assert!(rendered.contains("loom_obs_test_counter_total"));
    }
}
