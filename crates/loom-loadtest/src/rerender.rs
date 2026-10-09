// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Re-rendering a report a previous build of this binary wrote, under this
//! build's window placement and attribution (OBI-371).
//!
//! The need is concrete. Run `37880215784` (`7086b58`) reported 109 of 293
//! tail samples attributed to server stalls while its own latency timeline
//! showed 249 at-or-over-SLA samples in the single bucket in which the world
//! loop stalled for 875 ms. The bug was in how windows were placed, not in
//! what was measured -- and the fix's evidence is that same artifact, re-read.
//!
//! That is only possible if a report carries what attribution runs on, so a
//! report now keeps its scrape series (with wall-clock stamps), its
//! at-or-over-SLA samples, and its bucket widths. Where an archived report
//! predates one of those, this module says so in the notes it appends rather
//! than quietly computing something weaker and calling it the same number.
//!
//! What a re-render never touches is the gate: `e1_1_pass` and the p99 in
//! `command_latency` come from the run's own measurements and are carried
//! through unchanged.

use std::path::PathBuf;

use crate::report::{AttributionWindows, RunReport, TimelineBucket, attribute_samples};
use crate::server_metrics::{self, StallWindowPrecision};

/// `--rerender <report.json> [--out <prefix>]`. Returns the process exit code.
pub fn run(argv: &[String]) -> i32 {
    match Request::parse(argv).and_then(|req| req.execute()) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            2
        }
    }
}

#[derive(Debug)]
struct Request {
    input: PathBuf,
    /// Write the re-rendered report here. Without it the markdown goes to
    /// stdout only, which is what a human asks for and what a CI step does not.
    out_prefix: Option<PathBuf>,
}

impl Request {
    /// `argv` starts at the `--rerender` token itself.
    fn parse(argv: &[String]) -> Result<Self, String> {
        let mut input = None;
        let mut out_prefix = None;
        let mut i = 1;
        while i < argv.len() {
            let arg = argv[i].as_str();
            let next = |i: usize| argv.get(i).cloned();
            match arg {
                "--out" => {
                    i += 1;
                    out_prefix = Some(PathBuf::from(
                        next(i).ok_or_else(|| "--out needs a value".to_string())?,
                    ));
                }
                other if other.starts_with('-') => {
                    return Err(format!("unknown --rerender argument: {other}"));
                }
                path => {
                    if input.is_some() {
                        return Err(format!("--rerender takes one report path, not {path}"));
                    }
                    input = Some(PathBuf::from(path));
                }
            }
            i += 1;
        }
        Ok(Self {
            input: input.ok_or_else(|| "--rerender needs a <report.json> path".to_string())?,
            out_prefix,
        })
    }

    fn execute(&self) -> Result<(), String> {
        let text = std::fs::read_to_string(&self.input)
            .map_err(|e| format!("reading {}: {e}", self.input.display()))?;
        let mut report: RunReport = serde_json::from_str(&text)
            .map_err(|e| format!("parsing {}: {e}", self.input.display()))?;
        let outcome = re_render(&mut report, &self.input.display().to_string());
        let markdown = report.to_markdown();
        if let Some(prefix) = &self.out_prefix {
            if let Some(parent) = prefix.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            // Append, do not replace: `with_extension` on a prefix that
            // already contains a dot (`results/ci-e1-1.rerendered`) would eat
            // it and overwrite the original report.
            let json_path = PathBuf::from(format!("{}.json", prefix.display()));
            let md_path = PathBuf::from(format!("{}.md", prefix.display()));
            std::fs::write(
                &json_path,
                serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            std::fs::write(&md_path, &markdown).map_err(|e| e.to_string())?;
        }
        // On stderr, so a CI step can grep it into the job summary while the
        // markdown on stdout stays the report itself.
        eprintln!("{}", outcome.summary());
        println!("{markdown}");
        Ok(())
    }
}

/// What a re-render managed to recompute, and how far that reaches. The
/// prose it wrote into the report is in `report.notes`; this is the same
/// facts in machine-readable form, for a CI step that wants to grep them.
#[derive(Debug)]
pub struct Outcome {
    /// Whether the rebuilt stall windows carry the server's own timestamps.
    pub precision: StallWindowPrecision,
    /// Tail samples this re-render re-attributed, and how they landed.
    pub tail_count: usize,
    pub server_stall: usize,
    pub server_stall_precise: usize,
    pub unattributed: usize,
    /// The same numbers in the archived report, for the before/after line.
    pub archived_server_stall: usize,
    pub archived_tail_count: usize,
    pub archived_unattributed: usize,
    /// At-or-over-SLA samples in a bucket the rebuilt windows overlap, and the
    /// total over-SLA count, both read from the timeline. Needed because a
    /// report written before `tail_samples_over_sla` carries only its slowest
    /// samples, not its tail.
    pub bucket_level_attributed: usize,
    pub bucket_level_total: usize,
    /// `false` when the archived report carried only its slowest samples, so
    /// `tail_count` covers those and not the whole tail.
    pub sample_level_complete: bool,
}

impl Outcome {
    /// One line of plain text: the evidence a CI log or a human reading the
    /// shell wants, without the report's prose around it.
    pub fn summary(&self) -> String {
        let sample_part = if self.tail_count == 0 {
            "sample level: nothing was at or over the SLA, so there is no tail to attribute"
                .to_string()
        } else if self.sample_level_complete {
            format!(
                "sample level: {}/{} tail samples attributed to a server stall ({} inside a measured window), {} unattributed",
                self.server_stall, self.tail_count, self.server_stall_precise, self.unattributed
            )
        } else {
            format!(
                "sample level: {}/{} carried samples attributed to a stall (report predates `tail_samples_over_sla`, so the tail itself is not in it)",
                self.server_stall, self.tail_count
            )
        };
        format!(
            "re-render: was {}/{} attributed with {} unattributed, now {}; {}; bucket level: {}/{} over-SLA samples overlap a stall window; windows: {}",
            self.archived_server_stall,
            self.archived_tail_count,
            self.archived_unattributed,
            self.server_stall,
            sample_part,
            self.bucket_level_attributed,
            self.bucket_level_total,
            self.precision.sentence(),
        )
    }
}

/// Rebuild the server windows from the report's own scrape series, re-attribute
/// its tail against them, re-mark its timeline, and record in `report.notes`
/// exactly how much of that was possible. The gate numbers are left alone.
pub fn re_render(report: &mut RunReport, source: &str) -> Outcome {
    let (windows, stalls) = server_metrics::server_windows(&report.server_timeline);
    let precision = stalls.precision();
    let archived = report.tail_attribution.clone();

    // A report written before `tail_samples_over_sla` existed carries only its
    // slowest samples. Those are still worth re-attributing -- they are the
    // samples that decide whether a tail is a stall or a shift -- but they are
    // not the tail, and saying "20 of 20" where the run had 293 would be a lie
    // of omission. The timeline's per-bucket `over_sla` counts are the way to
    // state the rest without the samples.
    let sample_level_complete = !report.tail_samples_over_sla.is_empty();
    let tail = if sample_level_complete {
        report.tail_samples_over_sla.clone()
    } else {
        report.tail_samples.clone()
    };

    let attribution = if report.commands_sent == 0 && tail.is_empty() {
        None
    } else {
        Some(attribute_samples(
            &tail,
            report.sla_p99_ms,
            report.command_latency.as_ref().map_or(0.0, |r| r.p99_ms),
            // Re-ranking p99 without stall samples needs every sample of the
            // run, which no report carries. Inherit the archived value and say
            // so in the note.
            archived
                .as_ref()
                .map_or(0.0, |a| a.p99_excluding_server_stall_ms),
            &AttributionWindows {
                server_stall_windows: if report.server_instrumented {
                    windows.clone()
                } else {
                    Vec::new()
                },
                bot_starvation_windows: archived
                    .as_ref()
                    .map(|a| a.bot_starvation_windows.clone())
                    .unwrap_or_default(),
                login_ramp_end_ms: archived.as_ref().map_or(0, |a| a.login_ramp_end_ms),
                scrape_resolution_ms: archived.as_ref().map_or(0, |a| a.scrape_resolution_ms),
                stall_window_precision: precision,
            },
        ))
    };

    // Re-mark the timeline. Reports written before a bucket recorded its width
    // do not have one, so derive it from the grid the report describes before
    // asking `mark_server_stalls` to trust it.
    let mut buckets = report.latency_timeline.clone();
    infer_bucket_widths(&mut buckets);
    if report.server_instrumented {
        TimelineBucket::mark_server_stalls(&mut buckets, &windows);
    }
    let bucket_level_total: usize = buckets.iter().map(|b| b.over_sla).sum();
    // Without an instrumented series there is nothing to re-derive from, and
    // the archived marks are the run's own claim. Counting them as if this
    // re-render had produced them would report a rebuilt attribution that did
    // not happen, so the bucket-level figures stay zero and the note says why.
    let bucket_level_attributed = if report.server_instrumented {
        buckets
            .iter()
            .filter(|b| b.server_stalled == Some(true))
            .map(|b| b.over_sla)
            .sum()
    } else {
        0
    };
    report.latency_timeline = buckets;
    if let Some(a) = &attribution {
        report.tail_attribution = Some(a.clone());
    }

    let mut note = format!(
        "re-rendered by `loom-loadtest --rerender` from {source}: stall windows rebuilt from the report's own scrape series ({}), tail re-attributed against them, timeline re-marked. `p99_excluding_server_stall_ms` is inherited from the archived report -- re-ranking it needs every sample, which a report does not carry. p99 and the E1.1 gate are the archived run's measurements, unchanged.",
        precision.sentence()
    );
    if let Some(old) = &archived {
        note.push_str(&format!(
            " Attribution before this build: {} of {} tail samples against a server stall, {} unattributed. After: {} of {} against a stall ({} of them inside a measured window), {} unattributed.",
            old.server_stall,
            old.tail_count,
            old.unattributed,
            attribution.as_ref().map_or(0, |a| a.server_stall),
            attribution.as_ref().map_or(0, |a| a.tail_count),
            attribution.as_ref().map_or(0, |a| a.server_stall_precise),
            attribution.as_ref().map_or(0, |a| a.unattributed),
        ));
    }
    if !sample_level_complete && attribution.as_ref().is_some_and(|a| a.tail_count > 0) {
        note.push_str(&format!(
            " This report predates `tail_samples_over_sla` and carries only its {} slowest samples, so the sample-level figures above cover those, not the whole tail.{}",
            tail.len(),
            if report.server_instrumented {
                format!(
                    " Read together with the timeline, {} of {} at-or-over-SLA samples fall in a bucket the rebuilt windows overlap.",
                    bucket_level_attributed, bucket_level_total
                )
            } else {
                String::new()
            }
        ));
    }
    if report.command_latency.is_none() {
        note.push_str(" The archived report holds no command latency: nothing to attribute.");
    }
    if !report.server_instrumented {
        note.push_str(
            " The archived run scraped no instrumented server, so no windows were rebuilt: the timeline keeps the stall marks the run wrote, and the bucket-level figures are not this re-render's claim.",
        );
    }
    // The note belongs to the report, not to the caller: a re-rendered JSON
    // that did not carry its own provenance would be read as if the numbers
    // had come from the run.
    report.notes.push(note.clone());

    Outcome {
        precision,
        tail_count: attribution.as_ref().map_or(0, |a| a.tail_count),
        server_stall: attribution.as_ref().map_or(0, |a| a.server_stall),
        server_stall_precise: attribution.as_ref().map_or(0, |a| a.server_stall_precise),
        unattributed: attribution.as_ref().map_or(0, |a| a.unattributed),
        archived_server_stall: archived.as_ref().map_or(0, |a| a.server_stall),
        archived_tail_count: archived.as_ref().map_or(0, |a| a.tail_count),
        archived_unattributed: archived.as_ref().map_or(0, |a| a.unattributed),
        bucket_level_attributed,
        bucket_level_total,
        sample_level_complete,
    }
}

/// Reports written before a bucket recorded its own width still describe a
/// uniform grid, so the smallest gap between bucket starts *is* the width.
/// With fewer than two buckets there is no gap to read: leave the width unset
/// and let those buckets stay "not observed" rather than be marked against a
/// guessed one.
fn infer_bucket_widths(buckets: &mut [TimelineBucket]) {
    if buckets.len() < 2 {
        return;
    }
    let mut starts: Vec<u64> = buckets.iter().map(|b| b.start_ms).collect();
    starts.sort_unstable();
    let width = starts
        .windows(2)
        .filter_map(|w| w[1].checked_sub(w[0]))
        .min();
    if let Some(width) = width.filter(|w| *w > 0) {
        for b in buckets.iter_mut().filter(|b| b.bucket_ms == 0) {
            b.bucket_ms = width;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribution::{TailAttribution, TailSample, Window};
    use crate::report::LatencyReport;
    use crate::server_metrics::ServerRow;

    /// An archived report in the shape `7086b58` wrote: no `unix_ms` on its
    /// rows, no bucket widths, no at-or-over-SLA sample set -- only its 20
    /// slowest samples, a timeline whose worst bucket holds 249 over-SLA
    /// samples, and an attribution that explains 109 of 293 -- because its
    /// window builder could not place the run's worst stall at all.
    fn archived_report() -> RunReport {
        // The series the run actually scraped: nothing at t+10.3 s, then the
        // stall counter at 1 and 875 ms of stall time at t+11.3 s.
        let rows = vec![
            ServerRow {
                at_ms: 10_304,
                unix_ms: None,
                counters: crate::server_metrics::WorldCounters::default(),
            },
            ServerRow {
                at_ms: 11_304,
                unix_ms: None,
                counters: crate::server_metrics::WorldCounters {
                    ticks: Some(1_130.0),
                    stalls: Some(1.0),
                    stall_ms: Some(875.0),
                    duration_ms_max: Some(875.0),
                    ..Default::default()
                },
            },
        ];
        let buckets = vec![
            TimelineBucket {
                start_ms: 5_000,
                bucket_ms: 0,
                count: 1_400,
                p50_ms: 12.0,
                p95_ms: 30.0,
                p99_ms: 44.0,
                max_ms: 60.0,
                mean_ms: 15.0,
                over_sla: 0,
                server_stalled: Some(false),
            },
            TimelineBucket {
                start_ms: 10_000,
                bucket_ms: 0,
                count: 2_000,
                p50_ms: 40.0,
                p95_ms: 900.0,
                p99_ms: 990.0,
                max_ms: 996.0,
                mean_ms: 120.0,
                over_sla: 249,
                server_stalled: Some(true),
            },
        ];
        RunReport {
            players: 150,
            slow_reader_fraction: 0.1,
            requested_duration_secs: 120,
            actual_duration_secs: 120.0,
            login_failures: 0,
            disconnects: 0,
            commands_sent: 4_200,
            sla_p99_ms: 50.0,
            command_latency: Some(LatencyReport {
                count: 4_200,
                p50_ms: 14.0,
                p95_ms: 320.0,
                p99_ms: 980.0,
                max_ms: 996.0,
                mean_ms: 60.0,
            }),
            slow_reader_command_latency: None,
            login_latency: None,
            login_auth_latency: None,
            prompt_timeouts: 0,
            e1_1_pass: false,
            notes: vec![],
            latency_timeline: buckets,
            tail_samples: (0..20)
                .map(|i| TailSample {
                    at_ms: 10_308 + i * 8,
                    latency_ms: 996.0 - i as f64 * 4.0,
                })
                .collect(),
            tail_samples_over_sla: vec![],
            tail_attribution: Some(TailAttribution {
                threshold_ms: 50.0,
                tail_count: 293,
                login_ramp: 167,
                bot_starvation: 0,
                server_stall: 109,
                server_stall_precise: 0,
                server_stall_pct: 37.2,
                unattributed: 17,
                p99_ms: 980.0,
                p99_excluding_server_stall_ms: 40.0,
                server_stall_windows: vec![Window::exact(13_303, 14_302, 2, 108)],
                bot_starvation_windows: vec![],
                login_ramp_end_ms: 12_081,
                scrape_resolution_ms: 1_000,
                stall_window_precision: StallWindowPrecision::ScrapeInterval,
            }),
            server_timeline: rows,
            server_instrumented: true,
            bot_timer_lag: None,
            server_metrics: None,
        }
    }

    #[test]
    fn an_archived_report_re_renders_with_the_stall_it_missed() {
        let archived = archived_report();
        let mut report = archived_report();
        let outcome = re_render(&mut report, "ci-e1-1.json");

        // The 875 ms stall is now a window, placed by the counter series alone.
        let a = report.tail_attribution.clone().unwrap();
        assert_eq!(a.server_stall_windows.len(), 1, "{a:?}");
        assert_eq!(a.server_stall_windows[0].stall_ms, 875);
        assert!(a.server_stall_windows[0].approximate);

        // Every sample the archive carried was sent into it. Before, 109 of
        // 293 looked attributable and 17 were called unexplained; the top-20
        // set is now fully explained, and the timeline -- which is the only
        // place the run's full tail still exists -- says 249 of 293 over-SLA
        // samples sit in a bucket the rebuilt window overlaps.
        assert_eq!(
            (outcome.archived_server_stall, outcome.archived_tail_count),
            (109, 293)
        );
        assert_eq!((outcome.server_stall, outcome.tail_count), (20, 20));
        assert_eq!(outcome.unattributed, 0);
        assert_eq!(
            (outcome.bucket_level_attributed, outcome.bucket_level_total),
            (249, 249)
        );
        assert!(!outcome.sample_level_complete);
        assert_eq!(
            outcome.precision,
            StallWindowPrecision::ScrapeInterval,
            "no absolute stamps in the archive, so brackets only"
        );
        assert!(
            report.latency_timeline.iter().all(|b| b.bucket_ms == 5_000),
            "the grid width is read back out of the report"
        );
        // Both buckets end up marked: a bracket widened back to t+9.429 s
        // straddles the 5 s/10 s edge, and the report says so -- the window
        // column reads `bracket`, not `measured`.
        assert_eq!(
            report
                .latency_timeline
                .iter()
                .map(|b| b.server_stalled)
                .collect::<Vec<_>>(),
            vec![Some(true), Some(true)]
        );
        // The note is the part a human reads in the report itself.
        assert!(
            report.notes[0].contains("109 of 293"),
            "{}",
            report.notes[0]
        );
        assert!(report.notes[0].contains("20 of 20"), "{}", report.notes[0]);
        assert!(
            report.notes[0].contains("249 of 249"),
            "{}",
            report.notes[0]
        );
        assert!(
            outcome
                .summary()
                .contains("was 109/293 attributed with 17 unattributed, now 20")
        );
        // The gate and its measured number are untouched, and the markdown
        // admits that its own percentages cover 20 samples, not the 293.
        assert_eq!(report.e1_1_pass, archived.e1_1_pass);
        assert_eq!(
            report.command_latency.as_ref().unwrap().p99_ms,
            archived.command_latency.as_ref().unwrap().p99_ms
        );
        let md = report.to_markdown();
        assert!(
            md.contains("carries only its 20 slowest samples"),
            "the tail percentages must not read as if they covered all 293:\n{md}"
        );
    }

    #[test]
    fn a_report_that_carries_its_whole_tail_is_attributed_at_sample_level() {
        let mut report = archived_report();
        // What a report written by this build carries: every over-SLA sample,
        // and the server's own stamps on the scrape that records the stall.
        report.tail_samples_over_sla = (0..249)
            .map(|i| TailSample {
                at_ms: 9_600 + i * 6,
                latency_ms: 300.0,
            })
            .collect();
        let outcome = re_render(&mut report, "run.json");
        assert!(outcome.sample_level_complete);
        assert_eq!(outcome.tail_count, 249);
        assert_eq!(outcome.server_stall, 249, "{outcome:?}");
        assert_eq!(outcome.unattributed, 0);
    }

    #[test]
    fn an_uninstrumented_archive_is_said_so_not_so() {
        let mut report = archived_report();
        report.server_instrumented = false;
        report.server_timeline = vec![];
        let outcome = re_render(&mut report, "run.json");
        assert_eq!(
            outcome.precision,
            StallWindowPrecision::NotPlaced,
            "an empty scrape series places nothing"
        );
        assert_eq!(outcome.server_stall, 0);
        assert_eq!(outcome.bucket_level_attributed, 0);
        assert_eq!(outcome.bucket_level_total, 249);
        assert!(
            report
                .notes
                .last()
                .unwrap()
                .contains("not this re-render's claim"),
            "{}",
            report.notes.last().unwrap()
        );
        // With no rebuilt windows the archived marks are the only claim there
        // is, so they stay as the archive wrote them rather than being
        // rewritten to "no stalls".
        assert_eq!(
            report
                .latency_timeline
                .iter()
                .map(|b| b.server_stalled)
                .collect::<Vec<_>>(),
            vec![Some(false), Some(true)]
        );
        assert!(report.latency_timeline.iter().all(|b| b.bucket_ms == 5_000));
        // The 20 samples the archive carried were sent inside its own recorded
        // login ramp, so with the server side gone they land there, not in
        // "unexplained".
        let a = report.tail_attribution.clone().unwrap();
        assert_eq!((a.login_ramp, a.unattributed), (20, 0), "{a:?}");
        // Nothing invented: the archived windows are gone, because the rebuilt
        // set is what the report's own series supports.
        assert!(a.server_stall_windows.is_empty());
    }

    #[test]
    fn an_archive_from_before_the_new_fields_still_re_renders() {
        // The committed runs under `results/` were written by drivers that had
        // no attribution, no server series, no `prompt_timeouts`. A re-render
        // that only works on reports written by today's binary is a demo, not
        // a tool, so the fields a run gained later are all defaulted -- while
        // the ones the gate verdict is made of stay required.
        let minimal = r#"{
            "players": 150,
            "slow_reader_fraction": 0.1,
            "requested_duration_secs": 90,
            "actual_duration_secs": 90.9,
            "login_failures": 0,
            "disconnects": 0,
            "commands_sent": 9764,
            "sla_p99_ms": 50.0,
            "command_latency": {
                "count": 9764, "p50_ms": 41.0, "p95_ms": 44.8, "p99_ms": 46.9,
                "max_ms": 59.1, "mean_ms": 41.9
            },
            "e1_1_pass": true
        }"#;
        let mut report: RunReport = serde_json::from_str(minimal).unwrap();
        let outcome = re_render(&mut report, "2026-09-27-150-players.json");
        assert_eq!(outcome.precision, StallWindowPrecision::NotPlaced);
        assert_eq!(outcome.tail_count, 0);
        assert_eq!(outcome.bucket_level_attributed, 0);
        assert!(report.e1_1_pass, "the verdict is the archive's, unchanged");
        assert_eq!(
            report.command_latency.as_ref().unwrap().p99_ms,
            46.9,
            "the gate's number survives the re-render"
        );
        assert!(
            !report.notes[0].contains("holds no command latency"),
            "this archive does have command latency: {}",
            report.notes[0]
        );
        assert!(
            report.notes[0].contains("not this re-render's claim"),
            "an uninstrumented archive must not be reported as a rebuild: {}",
            report.notes[0]
        );
    }

    #[test]
    fn an_output_prefix_that_already_has_a_dot_is_appended_to_not_replaced() {
        // `--out results/ci-e1-1.rerendered` must not clobber
        // `results/ci-e1-1.json` by eating the `.rerendered` as an extension.
        let dir = std::env::temp_dir().join(format!("loom-rerender-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("report.json");
        let mut report = archived_report();
        report.notes.push("keep me".to_string());
        std::fs::write(&src, serde_json::to_string_pretty(&report).unwrap()).unwrap();
        let prefix = dir.join("report.rerendered");
        let req = Request {
            input: src.clone(),
            out_prefix: Some(prefix.clone()),
        };
        req.execute().unwrap();
        let wrote_json = dir.join("report.rerendered.json");
        let wrote_md = dir.join("report.rerendered.md");
        assert!(wrote_json.exists(), "{} missing", wrote_json.display());
        assert!(wrote_md.exists(), "{} missing", wrote_md.display());
        assert!(
            std::fs::read_to_string(&src).unwrap().contains("keep me"),
            "the source archive must come out of a re-render untouched"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_request_needs_a_report_path_and_takes_an_output_prefix() {
        let arg = |s: &str| s.to_string();
        let req = Request::parse(&[
            arg("--rerender"),
            arg("results/a.json"),
            arg("--out"),
            arg("results/b"),
        ])
        .unwrap();
        assert_eq!(req.input, PathBuf::from("results/a.json"));
        assert_eq!(req.out_prefix, Some(PathBuf::from("results/b")));
        assert!(
            Request::parse(&[arg("--rerender")])
                .unwrap_err()
                .contains("needs a <report.json> path")
        );
        assert!(
            Request::parse(&[arg("--rerender"), arg("a.json"), arg("--verbose")])
                .unwrap_err()
                .contains("unknown --rerender argument")
        );
        assert!(
            Request::parse(&[arg("--rerender"), arg("a.json"), arg("b.json")])
                .unwrap_err()
                .contains("one report path")
        );
    }
}
