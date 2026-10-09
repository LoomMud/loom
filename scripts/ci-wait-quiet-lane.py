#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Oberfield
# SPDX-License-Identifier: AGPL-3.0-only
"""Make the load lane measure the world, not the host (OBI-403).

The lane group ``loom-ci-load-lane`` makes the *job* exclusive. It does not make
the *host* exclusive, and ``loadtest-e1-1`` has only ``needs: classify``, so a
run's own ``rust`` job -- a full workspace release build plus test, the heaviest
thing the pool does -- can be running while that same run measures p99. On
2026-10-09 every measurement with that overlap went red and every measurement
without it went green: main runs 37925921869 (load1 6.63, ``rust`` in flight,
p99 177 ms) and 37927307391 (load1 19.41, 14 runnable tasks, p99 821 ms) against
PR runs 37926281183 (load1 6.20, ``rust`` finished, p99 22.6 ms) and 37927466029
(load1 5.38, same, p99 23.5 ms). The gate was reporting the host's schedule as a
latency regression.

Three modes:

``wait``       Poll *this run's* job list until no non-lane job of the run is
               still in flight **and** the host-side probes look idle, for
               ``--stability-samples`` consecutive polls. Records
               ``lane_wait_seconds``, the load average at the first poll and at
               the grant, and whatever was still running. If the host never gets
               quiet it exits 1 with ``verdict=inconclusive`` *before any
               measurement step runs*: "the lane never got quiet" is a different
               finding from "the world missed its SLA", and an inconclusive run
               must not masquerade as a regression.

``sample``     Tick every ``--interval-secs`` while the measurement runs,
               appending one line of host counters to a TSV. Reading ``/proc``
               costs essentially nothing, and the report's ``latency_timeline``
               is bucketed on the same 5 s boundary, so the two line up.

``correlate``  Join those samples against the report: for every bucket that
               missed the SLA, print what the host was doing in the same window,
               and say in one line whether the tail coincided with contention.
               This is what makes the next red self-attributing instead of
               arguable.

Why the ceiling is where it is. The two green gates measured at 1-minute load
average 6.20 and 5.38 on the same 8-CPU host that the red at 6.63 measured on,
so load average alone cannot separate the populations -- the job-list half is
what does that. The ceiling is therefore deliberately generous at 1.0 x the CPUs
visible to the runner: it stops a saturated host (19.41) from being measured
against, and does not stall a normal one (6.20). Every probe is recorded whether
or not it gates, so a month of runs says whether CPU utilisation and pressure
stall information deserve to gate too. Observability before optimization.

Usage:
  ci-wait-quiet-lane.py wait       [--stage NAME] [--out DIR] [--deadline-secs N]
                                   [--interval-secs N] [--stability-samples N]
                                   [--loadavg-ceiling X] [--cpu-busy-ceiling X]
  ci-wait-quiet-lane.py sample     --out FILE [--interval-secs N] [--max-secs N]
  ci-wait-quiet-lane.py correlate  --report FILE --samples FILE (--t0-epoch N |
                                   --t0-file F) --out FILE [--stage NAME]
  ci-wait-quiet-lane.py --self-test
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from email.message import Message
from typing import Optional

DEFAULT_API_BASE = "https://api.github.com"
# Jobs that may legitimately be in flight while a lane job waits: the three
# gates are chained (`loadtest-e1-1 -> loadtest-smoke -> bench`) inside one run,
# so the later two are `queued` while the first one measures. Waiting for those
# would deadlock the chain, so they are excluded by name, along with the job we
# are running in (`GITHUB_JOB`).
LANE_JOB_NAMES = ("loadtest-e1-1", "loadtest-smoke", "bench")
TERMINAL_JOB_STATUS = "completed"
# Build-shaped processes on this machine are contention by definition. The ARC
# runners give every job its own container, so a foreign tenant's `cargo build
# --release` is invisible here -- this is a backstop for a shared-runner host,
# not the primary signal. See `job_list` in the output for the signal that does
# the work.
BUILDER_PATTERNS = (r"cargo (build|test|bench|run)", r"(^|/)rustc ", r"cc1[a-z]* ")
# An HTTP failure that waiting will not fix: the token lacks `actions: read`, the
# repo/run id is wrong, or the endpoint refused us. Degrade to the host signals
# and say so loudly; `scripts/check-ci-load-lane.py` rule 14 pins the permission
# in `hygiene`, where a config mistake is unambiguous instead of intermittent.
PERMANENT_API_CODES = (401, 403, 404)
LOADAVG_FILE = "/proc/loadavg"
STAT_FILE = "/proc/stat"
PSI_FILE = "/proc/pressure/cpu"
CPU_FIELDS = ("user", "nice", "system", "idle", "iowait", "irq", "softirq",
              "steal", "guest", "guest_nice")
SAMPLE_HEADER = ("# epoch\tt_offset_secs\tload1\tload5\tprocs_running\ttotal_tasks"
                 "\tcpu_used_pct\tcpu_steal_pct\tpsi_some_total_us")


# ---------------------------------------------------------------- probes ----

def read_loadavg(path=LOADAVG_FILE):
    """(load1, load5, load15, runnable, total) or None.

    ``/proc/loadavg`` is not namespaced, so inside a runner container it is the
    *host's* number -- which is the point: it counts the other tenants' runnable
    tasks too.
    """
    try:
        fields = open(path).read().split()
        runnable, _, total = fields[3].partition("/")
        return (float(fields[0]), float(fields[1]), float(fields[2]),
                int(runnable), int(total))
    except (OSError, ValueError, IndexError):
        return None


def effective_cores():
    """CPUs the runner may actually use: nproc, capped by any cgroup quota."""
    cores = os.cpu_count() or 1
    try:
        quota = open("/sys/fs/cgroup/cpu.max").read().split()[:2]
        if quota and quota[0] != "max":
            cores = min(cores, max(1, int(float(quota[0]) / float(quota[1]))))
    except (OSError, ValueError, IndexError):
        pass
    try:
        quota = int(open("/sys/fs/cgroup/cpu/cpu.cfs_quota_us").read())
        period = int(open("/sys/fs/cgroup/cpu/cpu.cfs_period_us").read())
        if quota > 0 and period > 0:
            cores = min(cores, max(1, quota // period))
    except (OSError, ValueError):
        pass
    return cores


def read_proc_stat(path=STAT_FILE):
    """The aggregate `cpu` line plus procs_running/blocked, or None.

    `procs_running` is instantaneous rather than exponentially smoothed, which is
    the only host-side signal that separated the 2026-10-09 12:10:43 sample (14
    runnable of 1038) from the runs that passed (1 of 775, 2 of 773).
    """
    try:
        text = open(path).read()
    except OSError:
        return None
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if parts[:1] == ["cpu"]:
            vals = {n: int(v) for n, v in zip(CPU_FIELDS, parts[1:])}
            vals["total"] = sum(vals[n] for n in CPU_FIELDS if n in vals)
            out["cpu"] = vals
        elif len(parts) == 2 and parts[0] in ("procs_running", "procs_blocked"):
            out[parts[0]] = int(parts[1])
    return out if "cpu" in out else None


def cpu_percent(prev, cur):
    """(used_pct, steal_pct) between two /proc/stat reads, or (None, None)."""
    if not prev or not cur:
        return None, None
    delta = cur["cpu"]["total"] - prev["cpu"]["total"]
    if delta <= 0:
        return None, None
    idle = cur["cpu"].get("idle", 0) - prev["cpu"].get("idle", 0)
    iowait = cur["cpu"].get("iowait", 0) - prev["cpu"].get("iowait", 0)
    steal = cur["cpu"].get("steal", 0) - prev["cpu"].get("steal", 0)
    return (round(100.0 * (delta - idle - iowait) / delta, 2),
            round(100.0 * steal / delta, 2))


def read_psi(path=PSI_FILE):
    """(some_avg60, some_total_us) from pressure-stall information, or (None, None).

    Not all kernels export it, and the container's mount may show the cgroup
    rather than the host, so it is recorded for calibration and never gates.
    """
    try:
        for line in open(path):
            if line.startswith("some"):
                avg60 = re.search(r"avg60=([0-9.]+)", line)
                total = re.search(r"total=([0-9]+)", line)
                return (float(avg60.group(1)) if avg60 else None,
                        int(total.group(1)) if total else None)
    except (OSError, ValueError):
        pass
    return None, None


def our_pid_tree():
    """Our pid and our ancestors: something we started is not a foreign builder."""
    pids, pid = set(), os.getpid()
    while pid and pid > 0:
        pids.add(pid)
        try:
            m = re.search(r"^PPid:\s+(\d+)", open("/proc/%d/status" % pid).read(), re.M)
            pid = int(m.group(1)) if m else 0
        except (OSError, ValueError):
            pid = 0
    return pids


def foreign_builders(pgrep=None, mine=None):
    """Command lines of build-shaped processes we did not start.

    None means "this signal cannot see" (no `pgrep` in a minimal image), which
    the caller must not read as a quiet host.
    """
    pgrep = pgrep if pgrep is not None else _PGREP
    if not pgrep:
        return None
    mine = mine if mine is not None else our_pid_tree()
    found = []
    for pattern in BUILDER_PATTERNS:
        try:
            res = subprocess.run([pgrep, "-f", "-a", pattern], capture_output=True,
                                 text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            return None
        for line in (res.stdout or "").splitlines():
            pid, _, cmd = line.strip().partition(" ")
            try:
                pid_i = int(pid)
            except ValueError:
                continue
            # One process can match several patterns (`cargo build` spawns `cc1plus`
            # and `rustc`); count the command line once, not once per pattern.
            if pid_i in mine or not cmd or cmd[:120] in found:
                continue
            found.append(cmd[:120])
    return found


_PGREP = "pgrep"  # resolved at import; injectable for the self-test


def resolve_tools(env=None):
    """Set `_PGREP` from PATH; a minimal image without pgrep loses that one signal."""
    global _PGREP
    env = env if env is not None else os.environ
    for directory in (env.get("PATH") or os.defpath).split(os.pathsep):
        candidate = os.path.join(directory, "pgrep")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            _PGREP = candidate
            return candidate
    _PGREP = None
    return None


class Host:
    """Host-side probes, diffed between successive calls to `sample()`.

    Every probe degrades to None ("cannot see") rather than to a value: a probe
    that failed must never be able to read as a quiet host.
    """

    def __init__(self, loadavg_file=LOADAVG_FILE, stat_file=STAT_FILE,
                 psi_file=PSI_FILE, cores=None, scan_procs=True, pgrep=_PGREP):
        self.loadavg_file = loadavg_file
        self.stat_file = stat_file
        self.psi_file = psi_file
        self.cores = cores or effective_cores()
        self.scan_procs = scan_procs
        self.pgrep = pgrep
        self._prev_stat = None
        self._prev_psi_total = None

    def sample(self):
        load = read_loadavg(self.loadavg_file)
        stat = read_proc_stat(self.stat_file)
        used, steal = cpu_percent(self._prev_stat, stat)
        self._prev_stat = stat
        avg60, total = read_psi(self.psi_file)
        psi_delta = None
        if total is not None:
            if self._prev_psi_total is not None:
                psi_delta = total - self._prev_psi_total
            self._prev_psi_total = total
        return {
            "load1": load[0] if load else None,
            "load5": load[1] if load else None,
            "runnable": load[3] if load else None,
            "total_tasks": load[4] if load else None,
            "procs_running": (stat or {}).get("procs_running"),
            "cpu_used_pct": used,
            "cpu_steal_pct": steal,
            "psi_some_avg60": avg60,
            "psi_some_delta_us": psi_delta,
            "builders": foreign_builders(self.pgrep) if self.scan_procs else None,
        }


# ------------------------------------------------------------ job list ----

class JobList:
    """`GET /repos/{repo}/actions/runs/{run_id}/jobs` for the current run.

    Read-only, default `GITHUB_TOKEN` (needs `actions: read`, which
    `scripts/check-ci-load-lane.py` rule 14 pins on each lane job). A
    401/403/404 is permanent for the life of the process: we then gate on the
    host signals alone and record that the precise half was blind, rather than
    redding a required check over a permissions block.
    """

    def __init__(self, env=None, opener=None):
        env = env if env is not None else os.environ
        self.repo = env.get("GITHUB_REPOSITORY", "")
        self.run_id = env.get("GITHUB_RUN_ID", "")
        self.token = env.get("GITHUB_TOKEN") or env.get("GH_TOKEN") or ""
        base = env.get("GITHUB_API_URL") or DEFAULT_API_BASE
        self.opener = opener
        self.url = "%s/repos/%s/actions/runs/%s/jobs" % (
            base.rstrip("/"), self.repo or "unknown/unknown", self.run_id or "0")
        self.error = None
        self.permanent = False
        self.polls = 0
        if not self.repo or not self.run_id:
            self.permanent = True
            self.error = "GITHUB_REPOSITORY/GITHUB_RUN_ID are unset"

    def _get(self, url):
        if self.opener:
            return self.opener(url, self.token)
        headers = {"Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "loom-ci-wait-quiet-lane"}
        if self.token:
            headers["Authorization"] = "bearer " + self.token
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode())

    def fetch(self):
        """All jobs of this run, or None on failure (with `self.error` set)."""
        self.polls += 1
        jobs, page = [], 1
        while True:
            try:
                payload = self._get("%s?per_page=100&page=%d" % (self.url, page))
            except urllib.error.HTTPError as exc:
                self.error = "HTTP %s" % exc.code
                if exc.code in PERMANENT_API_CODES:
                    self.permanent = True
                return None
            except Exception as exc:  # network / DNS / JSON: transient, retry
                self.error = "%s: %s" % (type(exc).__name__, str(exc)[:120])
                return None
            batch = payload.get("jobs") or []
            jobs.extend(batch)
            if len(batch) < 100:
                return jobs
            page += 1

    def in_flight_nonlane(self, current_job=""):
        """This run's jobs that are neither a lane gate nor finished.

        `queued` counts: a job waiting for a runner has not started yet, and it
        will start while we would be measuring. Reaching `completed` is the point.
        Returns None when the list could not be read -- callers must not read that
        as "nothing is running".
        """
        jobs = self.fetch()
        if jobs is None:
            return None
        skip: set = {n.lower() for n in LANE_JOB_NAMES}
        if current_job:
            skip.add(current_job.lower())
        return [{"id": j.get("id"), "name": j.get("name"), "status": j.get("status"),
                 "conclusion": j.get("conclusion"), "started_at": j.get("started_at"),
                 "completed_at": j.get("completed_at")}
                for j in jobs
                if (j.get("name") or "").lower() not in skip
                and j.get("status") != TERMINAL_JOB_STATUS]


# --------------------------------------------------------------- verdict ----

def quiet_reasons(snap, in_flight, ceiling, busy_ceiling):
    """Why this poll is not quiet yet. An empty list means it is quiet.

    `in_flight=None` means the job list was unreadable: no job reason is raised
    (the caller gates on the host alone and reports the blind spot), so a
    permissions accident degrades the check instead of failing it.
    """
    reasons = []
    if in_flight:
        reasons.append("job(s) of this run still in flight: " + ", ".join(
            sorted("%s=%s" % (j["name"], j["status"]) for j in in_flight)))
    if snap["load1"] is None:
        reasons.append("load average unreadable")
    elif snap["load1"] > ceiling:
        reasons.append("load1 %.2f is above the %.2f ceiling" % (snap["load1"], ceiling))
    if busy_ceiling is not None and snap["cpu_used_pct"] is not None:
        if snap["cpu_used_pct"] > busy_ceiling:
            reasons.append("cpu utilisation %.1f%% is above the %.1f%% ceiling"
                           % (snap["cpu_used_pct"], busy_ceiling))
    if snap["builders"]:
        reasons.append("foreign builder: %s" % "; ".join(snap["builders"][:3]))
    return reasons


def fmt(value, spec="%.2f"):
    return (spec % value) if isinstance(value, (int, float)) else "n/a"


# ---------------------------------------------------------------- wait ----

def wait_for_quiet(args, host=None, jobs=None, now=time.time, sleep=time.sleep) -> dict:
    """Poll until the run's own non-lane jobs are finished and the host is idle.

    Returns the payload dict. `verdict` is `quiet` only when the stability streak
    was reached; a timeout is `inconclusive`, which the caller exits non-zero on
    *before* any measurement step runs. `now`/`sleep` are injected so the deadline
    math is tested in simulated milliseconds rather than by waiting 15 minutes.
    """
    host = host or Host(cores=args.cores or None, scan_procs=not args.skip_proc_scan,
                        loadavg_file=args.loadavg_file, stat_file=args.stat_file,
                        psi_file=args.psi_file)
    jobs = jobs or JobList()
    current_job = args.current_job or os.environ.get("GITHUB_JOB", "")
    ceiling = (args.loadavg_ceiling if args.loadavg_ceiling is not None
               else args.loadavg_factor * host.cores)
    start = now()
    granted = False
    streak_n = 0
    # `snap`/`first` hold the last and first host readings; both are dicts from
    # the first loop iteration on, so the empty dict is the sentinel rather than
    # None -- the payload subscripts them and an Optional would be a lie the
    # reader has to re-derive. The two `*_in_flight` values *are* Optional: a
    # blind job list has to stay distinguishable from "nothing in flight".
    snap: dict = {}
    first: dict = {}
    in_flight: Optional[list] = None
    first_in_flight: Optional[list] = None
    polls: list = []
    shown: Optional[list] = None
    while True:
        snap = host.sample()
        in_flight = None if jobs.permanent else jobs.in_flight_nonlane(current_job)
        if not first:
            first = dict(snap)
            first_in_flight = list(in_flight) if in_flight is not None else None
        reasons = quiet_reasons(snap, in_flight, ceiling, args.cpu_busy_ceiling)
        if in_flight is None and not jobs.permanent:
            # A transient failure to read the job list must not count toward the
            # streak: one dropped poll would otherwise be enough to grant a
            # measurement on a host whose `rust` job is still running.
            reasons = reasons + ["job list temporarily unavailable (%s)" % jobs.error]
        elapsed = now() - start
        if reasons:
            streak_n = 0
            polls.append({"t": round(elapsed, 1), "reasons": reasons,
                          "load1": snap["load1"],
                          "job_list": "unavailable" if in_flight is None else "ok"})
            # Throttle: a 15-minute wait at 10 s polls is 90 lines. Print when the
            # reason changes, and at most every 6 polls otherwise.
            if reasons != shown or len(polls) % 6 == 0:
                shown = reasons
                print("%6.0fs  not quiet: %s" % (elapsed, "; ".join(reasons)), flush=True)
        else:
            streak_n += 1
            print("%6.0fs  quiet (%d/%d)" % (elapsed, streak_n, args.stability_samples),
                  flush=True)
            if streak_n >= args.stability_samples:
                granted = True
                break
        if elapsed + args.interval_secs > args.deadline_secs:
            break
        sleep(args.interval_secs)
    wait_secs = round(now() - start, 1)
    return {
        "schema": 1,
        "stage": args.stage,
        "verdict": "quiet" if granted else "inconclusive",
        "lane_wait_seconds": wait_secs,
        "deadline_seconds": args.deadline_secs,
        "stability_samples": args.stability_samples,
        "interval_seconds": args.interval_secs,
        "runner_cores": host.cores,
        "loadavg_ceiling": round(ceiling, 2),
        "cpu_busy_ceiling": args.cpu_busy_ceiling,
        "runner_loadavg_start": first["load1"],
        "runner_loadavg_end": snap["load1"],
        "runner_cpu_used_start": first["cpu_used_pct"],
        "runner_cpu_used_end": snap["cpu_used_pct"],
        "runner_steal_start": first["cpu_steal_pct"],
        "runner_steal_end": snap["cpu_steal_pct"],
        "runner_procs_running_start": first["procs_running"],
        "runner_procs_running_end": snap["procs_running"],
        "runner_runnable_start": first["runnable"],
        "runner_runnable_end": snap["runnable"],
        "psi_some_avg60_end": snap["psi_some_avg60"],
        "pgrep": host.scan_procs and _PGREP or "unavailable",
        "foreign_builders_end": snap["builders"] or [],
        "job_list": ("ok" if in_flight is not None
                     else "unavailable: %s" % (jobs.error or "unknown")),
        "job_list_polls": jobs.polls,
        "nonlane_jobs_in_flight_at_first_poll": first_in_flight,
        "nonlane_jobs_in_flight_at_grant": in_flight or [],
        "not_quiet_polls": len(polls),
        "poll_log": polls[-12:],
        "last_reasons": polls[-1]["reasons"] if polls else [],
        "gate_granted_at_epoch": int(now()) if granted else None,
    }


def emit_wait(args, payload, summary_file=None):
    """Write the artifact, the step summary, and the workflow annotation."""
    os.makedirs(args.out, exist_ok=True)
    path = os.path.join(args.out, "quiet-host.json")
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=1, sort_keys=True)
        fh.write("\n")
    granted = payload["verdict"] == "quiet"
    lines = ["### `%s`: quiet-host gate (OBI-403)" % payload["stage"], "",
             "| signal | value |", "|---|---|",
             "| verdict | `%s` |" % payload["verdict"],
             "| lane_wait_seconds | %s |" % payload["lane_wait_seconds"],
             "| runner_loadavg_start | %s |" % fmt(payload["runner_loadavg_start"]),
             "| runner_loadavg_end | %s |" % fmt(payload["runner_loadavg_end"]),
             "| loadavg ceiling | %s (cpus visible: %s) |" % (
                 fmt(payload["loadavg_ceiling"]), payload["runner_cores"]),
             "| cpu used at grant | %s |" % fmt(payload["runner_cpu_used_end"]),
             "| steal at grant | %s |" % fmt(payload["runner_steal_end"]),
             "| procs_running at grant | %s |" % (
                 payload["runner_procs_running_end"] if payload["runner_procs_running_end"]
                 is not None else "n/a"),
             "| PSI some avg60 at grant | %s |" % fmt(payload["psi_some_avg60_end"]),
             "| run job list | `%s` (%s polls) |" % (payload["job_list"],
                                                     payload["job_list_polls"]),
             "| in flight at grant | %s |" % (
                 ", ".join("`%s`=%s" % (j["name"], j["status"])
                           for j in payload["nonlane_jobs_in_flight_at_grant"]) or "none"),
             "| foreign builders at grant | %s |" % (
                 ", ".join("`%s`" % b for b in payload["foreign_builders_end"]) or "none"),
             ]
    if not granted:
        lines += ["", "**The lane never got quiet inside %ss, so no measurement ran.** "
                      "This is *not* a p99 miss: the world thread was not measured. "
                      "Last reason: %s." % (payload["deadline_seconds"],
                                            "; ".join(payload["last_reasons"]) or "?")]
    block = "\n".join(lines) + "\n"
    destination = summary_file if summary_file is not None else args.summary_file
    if destination:
        try:
            with open(destination, "a") as fh:
                fh.write(block)
        except OSError:
            pass
    print(block, flush=True)
    return 0 if granted else 1


def cmd_wait(args, host=None, jobs=None, now=time.time, sleep=time.sleep):
    host = host or Host(cores=args.cores or None, scan_procs=not args.skip_proc_scan,
                        loadavg_file=args.loadavg_file, stat_file=args.stat_file,
                        psi_file=args.psi_file)
    jobs = jobs or JobList()
    payload = wait_for_quiet(args, host=host, jobs=jobs, now=now, sleep=sleep)
    code = emit_wait(args, payload)
    if payload["verdict"] == "quiet":
        if payload["job_list"].startswith("unavailable"):
            print("::warning title=OBI-403 quiet-host gate::the run's job list was "
                  "unavailable (%s), so only the host signals gated. Check the "
                  "`actions: read` permission on this job." % payload["job_list"],
                  flush=True)
        return code
    print("::error title=OBI-403 lane never got quiet (INCONCLUSIVE, not a p99 "
          "miss)::waited %ss for this run's non-lane jobs and an idle host; last "
          "reason: %s" % (payload["lane_wait_seconds"],
                          "; ".join(payload["last_reasons"]) or "?"), flush=True)
    return code


# -------------------------------------------------------------- sample ----

def cmd_sample(args):
    """Append one host-counter line every interval while the measurement runs."""
    dirname = os.path.dirname(args.out)
    if dirname:
        os.makedirs(dirname, exist_ok=True)
    prev = read_proc_stat(args.stat_file)
    t0 = time.time()
    with open(args.out, "a") as fh:
        if not os.path.getsize(args.out):
            fh.write(SAMPLE_HEADER + "\n")
            fh.flush()
        while True:
            time.sleep(args.interval_secs)
            cur = read_proc_stat(args.stat_file)
            used, steal = cpu_percent(prev, cur)
            prev = cur
            load = read_loadavg(args.loadavg_file)
            _, psi_total = read_psi(args.psi_file)
            row = [int(time.time()), round(time.time() - t0, 1),
                   load[0] if load else "n/a", load[1] if load else "n/a",
                   (cur or {}).get("procs_running", "n/a"),
                   load[4] if load else "n/a",
                   "n/a" if used is None else used,
                   "n/a" if steal is None else steal,
                   "n/a" if psi_total is None else psi_total]
            fh.write("\t".join(str(x) for x in row) + "\n")
            fh.flush()
            if time.time() - t0 >= args.max_secs:
                return 0


def read_samples(path):
    rows = []
    try:
        with open(path) as fh:
            for line in fh:
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 5:
                    continue

                def num(i):
                    return None if i >= len(parts) or parts[i] == "n/a" else float(parts[i])
                try:
                    rows.append({"epoch": int(float(parts[0])), "offset": num(1),
                                 "load1": num(2), "procs_running": num(4),
                                 "cpu_used_pct": num(6)})
                except ValueError:
                    continue
    except OSError:
        return []
    return rows


# ----------------------------------------------------------- correlate ----

def correlate(report, samples, t0, bucket_ms) -> list:
    """For each latency bucket of the report, what the host did in that window."""
    out = []
    for bucket in report.get("latency_timeline") or []:
        lo = (bucket.get("start_ms") or 0) / 1000.0
        hi = lo + bucket_ms / 1000.0
        window = [s for s in samples if t0 + lo <= s["epoch"] < t0 + hi]
        if not window:
            continue
        out.append({"start_s": lo, "over_sla": bucket.get("over_sla", 0),
                    "p99_ms": bucket.get("p99_ms"),
                    "host_load1_max": max(s["load1"] for s in window if s["load1"] is not None)
                    if any(s["load1"] is not None for s in window) else None,
                    "host_running_max": max((s["procs_running"] for s in window
                                             if s["procs_running"] is not None), default=None),
                    "host_used_max": max((s["cpu_used_pct"] for s in window
                                          if s["cpu_used_pct"] is not None), default=None),
                    "samples": len(window)})
    return out


def read_quiet_record(path):
    """The gate's own record, if we can read it. Never raises.

    `correlate` is the file a human reads next to an attribution table, and the
    single most useful fact about a number is whether the host was quiet while
    it was taken. That fact lives in `quiet-host.json`; without this the reader
    has to open two artifacts to know whether a green run was quiet at all.
    """
    if not path:
        return None
    try:
        with open(path) as fh:
            record = json.load(fh)
    except (OSError, ValueError):
        return None
    return record if isinstance(record, dict) and "lane_wait_seconds" in record else None


def cmd_correlate(args):
    """Join the host samples to the report's latency buckets. Never gates."""
    try:
        report = json.load(open(args.report))
    except (OSError, ValueError) as exc:
        print("host_vs_latency: no report to correlate (%s)" % exc, flush=True)
        return 0
    samples = read_samples(args.samples)
    if not samples:
        print("host_vs_latency: no host samples recorded, so this run cannot "
              "self-attribute -- check that the `sample` step ran", flush=True)
        return 0
    t0 = args.t0_epoch
    if t0 is None and args.t0_file:
        try:
            t0 = int(open(args.t0_file).read().strip())
        except (OSError, ValueError):
            t0 = None
    if t0 is None:
        print("host_vs_latency: the measurement start epoch is unknown", flush=True)
        return 0
    rows = correlate(report, samples, t0, args.bucket_ms)
    over = [r for r in rows if r["over_sla"]]
    cores = args.cores or effective_cores()
    busy = lambda r: ((r["host_used_max"] or 0) >= args.contention_pct
                      or (r["host_running_max"] or 0) >= cores)
    contention = [r for r in over if busy(r)]
    peak_load = max((s["load1"] for s in samples if s["load1"] is not None), default=None)
    peak_used = max((s["cpu_used_pct"] for s in samples if s["cpu_used_pct"] is not None),
                    default=None)

    def offset_of(key, value):
        """The t+offset of the first sample where `key` reached `value`."""
        return next((s["offset"] for s in samples if s.get(key) == value), None)
    lines = ["### `%s`: host vs latency (OBI-403)" % args.stage, ""]
    quiet = read_quiet_record(getattr(args, "quiet_host_file", ""))
    if quiet:
        lines += ["| quiet host (before the measurement) | value |", "|---|---|",
                  "| verdict | `%s` |" % quiet.get("verdict", "?"),
                  "| lane_wait_seconds | %s |" % fmt(quiet.get("lane_wait_seconds")),
                  "| loadavg at grant | %s (ceiling %s, %s cpus) |" % (
                      fmt(quiet.get("runner_loadavg_end")),
                      fmt(quiet.get("loadavg_ceiling")),
                      quiet.get("runner_cores", "?")),
                  "| run job list | `%s` (%s polls) |" % (quiet.get("job_list", "?"),
                                                          quiet.get("job_list_polls", "?")),
                  ""]
    else:
        wanted = getattr(args, "quiet_host_file", "")
        if wanted:
            lines += ["(`--quiet-host-file %s` was unreadable, so this run's quiet-host "
                      "verdict is not recorded next to the tail)" % wanted, ""]
    if over:
        lines += ["| bucket | over SLA | p99 ms | host load1 max | host cpu max "
                  "| procs_running max |", "|---|---|---|---|---|---|"]
        lines += ["| t+%ds | %s | %s | %s | %s | %s |" % (
            int(r["start_s"]), r["over_sla"], fmt(r["p99_ms"]), fmt(r["host_load1_max"]),
            fmt(r["host_used_max"]), fmt(r["host_running_max"], "%d")) for r in over]
    else:
        lines.append("No latency bucket missed the SLA, so there is no tail to attribute.")
    lines += ["", "host_vs_latency: buckets_over_sla=%d peak_load1=%s@t+%ds peak_cpu=%s@t+%ds "
              "samples=%d" % (len(over), fmt(peak_load),
                              int(offset_of("load1", peak_load) or 0),
                              fmt(peak_used), int(offset_of("cpu_used_pct", peak_used) or 0),
                              len(samples)),
              ""]
    if over and contention:
        lines.append("host_evidence: %d of %d over-SLA bucket(s) coincide with host "
                     "contention (>= %s%% cpu, or procs_running >= %s). Read this red as "
                     "a host finding first, not a world-thread regression." % (
                         len(contention), len(over), args.contention_pct, cores))
    elif over:
        lines.append("host_evidence: the host looked quiet (never >= %s%% cpu and never "
                     ">= %s runnable) while %d bucket(s) missed the SLA. That is a "
                     "world-thread finding: escalate it." % (
                         args.contention_pct, cores, len(over)))
    else:
        lines.append("host_evidence: nothing to attribute.")
    text = "\n".join(lines) + "\n"
    if args.out:
        dirname = os.path.dirname(args.out)
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        try:
            with open(args.out, "w") as fh:
                fh.write(text)
        except OSError:
            pass
    destination = args.summary_file
    if destination:
        try:
            with open(destination, "a") as fh:
                fh.write(text)
        except OSError:
            pass
    print(text, flush=True)
    return 0


# ------------------------------------------------------------- self-test ----

class FakeAPI:
    """Stand-in for the Actions jobs endpoint, driven by a per-poll plan.

    `plan` entries are either a status string for the run's `rust` job, or the
    literal "403"/"500" to make that poll fail.
    """

    def __init__(self, plan):
        self.plan = plan
        self.calls = 0

    def __call__(self, url, token):
        self.calls += 1
        step = self.plan[min(self.calls - 1, len(self.plan) - 1)]
        if step == "403":
            raise urllib.error.HTTPError(url, 403, "Forbidden", Message(), None)
        if step == "500":
            raise urllib.error.HTTPError(url, 500, "Server Error", Message(), None)
        if step == "garbage":
            raise urllib.error.URLError("no route")
        return {"jobs": [
            {"name": "rust", "status": step, "id": 1},
            {"name": "loadtest-e1-1", "status": "in_progress", "id": 2},
            {"name": "loadtest-smoke", "status": "queued", "id": 3},
            {"name": "bench", "status": "queued", "id": 4}]}


class Clock:
    """Deterministic time so the deadline math is testable in milliseconds."""

    def __init__(self, start=1000.0, tick=0.1):
        self.t = start
        self.tick = tick

    def time(self):
        value = self.t
        self.t += self.tick
        return value

    def sleep(self, secs):
        self.t += secs


class ScriptedHost:
    """A Host whose load average follows a script, so streak logic is testable.

    `loads` entries are floats, or None for "unreadable". The last entry repeats.
    """

    def __init__(self, loads, cores=8):
        self.loads = list(loads)
        self.cores = cores
        self.scan_procs = False
        self.calls = 0

    def sample(self):
        idx = min(self.calls, len(self.loads) - 1)
        self.calls += 1
        load1 = self.loads[idx]
        return {"load1": load1, "load5": load1, "runnable": 1 if load1 and load1 < 8 else 14,
                "total_tasks": 775, "procs_running": 1 if load1 and load1 < 8 else 14,
                "cpu_used_pct": None, "cpu_steal_pct": None, "psi_some_avg60": None,
                "psi_some_delta_us": None, "builders": None}


def loadavg_file(path, load1, runnable=1, total=775):
    with open(path, "w") as fh:
        fh.write("%.2f 4.00 8.00 %d/%d 1\n" % (load1, runnable, total))


def wait_args(tmp, **kw):
    d = dict(stage="self-test", out=tmp, deadline_secs=3, interval_secs=0.1,
             stability_samples=2, loadavg_ceiling=None, loadavg_factor=1.0,
             cpu_busy_ceiling=None, cores=8, skip_proc_scan=True, current_job="loadtest-e1-1",
             loadavg_file=os.path.join(tmp, "loadavg"), stat_file="/proc/stat",
             psi_file=PSI_FILE,
             summary_file=os.path.join(tmp, "summary.md"))
    d.update(kw)
    return argparse.Namespace(**d)


def http_server_selftest():
    """Exercise the real urllib path against an in-process server on localhost.

    Injecting an opener would test our own arithmetic but not the URL, the headers,
    or the bearer token -- which is the part a workflow run actually gets wrong.
    Same shape as the `legolas/obi-350` fake-github precedent.
    """
    import http.server
    import threading

    state = {"calls": 0}
    seen = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            state["calls"] += 1
            seen["auth"] = self.headers.get("Authorization")
            seen["accept"] = self.headers.get("Accept")
            seen["path"] = self.path
            body = json.dumps({"jobs": [{"name": "rust", "status": "completed",
                                        "id": 1}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):  # noqa: A002 - match the base class
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = "http://127.0.0.1:%d" % server.server_address[1]
    jobs = JobList(env={"GITHUB_API_URL": base, "GITHUB_REPOSITORY": "LoomMud/loom",
                        "GITHUB_RUN_ID": "1", "GITHUB_TOKEN": "s"},
                   opener=None)
    in_flight = jobs.in_flight_nonlane("loadtest-e1-1")
    server.shutdown()
    ok = (in_flight == [] and state["calls"] == 1
          and seen.get("auth") == "bearer s"
          and seen.get("accept") == "application/vnd.github+json"
          and seen.get("path", "").startswith(
              "/repos/LoomMud/loom/actions/runs/1/jobs?per_page=100&page=1"))
    return ok, "GET %s auth=%s accept=%s -> %s" % (seen.get("path"),
                                                   seen.get("auth"),
                                                   seen.get("accept"), in_flight)


def self_test():
    import tempfile

    failed = 0
    tmp = tempfile.mkdtemp(prefix="quiet-lane-selftest-")
    quiet_path = os.path.join(tmp, "loadavg")
    loadavg_file(quiet_path, 5.38)
    hot_path = os.path.join(tmp, "hot-loadavg")
    loadavg_file(hot_path, 19.41, runnable=14)

    def case(name, want_verdict, want_code, args, api_plan, kw):
        jobs = JobList(env={"GITHUB_REPOSITORY": "o/r", "GITHUB_RUN_ID": "7",
                            "GITHUB_TOKEN": "t"}, opener=FakeAPI(api_plan))
        clock = Clock()
        host = kw.get("host") or Host(cores=kw.get("cores", 8),
                                      loadavg_file=args.loadavg_file,
                                      stat_file=args.stat_file, scan_procs=False)
        # Drive it through `cmd_wait`, not the internals: the annotation text and
        # the exit code are the contract the workflow depends on.
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = cmd_wait(args, host=host, jobs=jobs, now=clock.time, sleep=clock.sleep)
        emitted = buffer.getvalue()
        payload = json.load(open(os.path.join(args.out, "quiet-host.json")))
        got = (payload["verdict"], code)
        ok = got == (want_verdict, want_code)
        checks = list(kw.get("asserts", []))
        checks.append(((lambda p: p["verdict"] != "quiet" or
                        "INCONCLUSIVE" not in emitted),
                       lambda p: "a quiet grant must not be labelled inconclusive"))
        if want_verdict != "quiet":
            checks.append(((lambda p: "INCONCLUSIVE, not a p99 miss" in emitted),
                           lambda p: "timeout annotation missing: %s" % emitted[-400:]))
        for check, detail in checks:
            if not check(payload):
                ok = False
                got = (got, detail(payload))
        return name, ok, got, payload

    cases = [
        # 1. The 2026-10-09 red-main shape: our own `rust` job is in flight the
        #    whole time. Host signals look fine (load 5.38 < 8), so this proves
        #    the job-list half is what blocks the measurement.
        ("rust stays in flight -> inconclusive", "inconclusive", 1,
         wait_args(tmp), ["in_progress"],
         dict(asserts=[(lambda p: p["lane_wait_seconds"] >= 2.5,
                        lambda p: "waited %s" % p["lane_wait_seconds"]),
                       (lambda p: "in flight" in " ".join(p["last_reasons"]),
                        lambda p: p["last_reasons"]),
                       (lambda p: p["nonlane_jobs_in_flight_at_grant"] and
                        p["nonlane_jobs_in_flight_at_grant"][0]["status"] == "in_progress",
                        lambda p: p["nonlane_jobs_in_flight_at_grant"]),
                       (lambda p: p["gate_granted_at_epoch"] is None,
                        lambda p: "granted anyway")])),
        # 2. The green-PR shape: `rust` finishes two polls in, then we grant. The
        #    lane's own queued `loadtest-smoke`/`bench` must never block it.
        ("rust completes -> quiet", "quiet", 0,
         wait_args(tmp), ["in_progress", "in_progress", "completed"],
         dict(asserts=[(lambda p: p["nonlane_jobs_in_flight_at_grant"] == [],
                        lambda p: p["nonlane_jobs_in_flight_at_grant"]),
                       (lambda p: p["nonlane_jobs_in_flight_at_first_poll"] and
                        p["nonlane_jobs_in_flight_at_first_poll"][0]["name"] == "rust",
                        lambda p: p["nonlane_jobs_in_flight_at_first_poll"]),
                       (lambda p: p["gate_granted_at_epoch"] is not None,
                        lambda p: "no grant epoch")])),
        # 3. Saturated host, all jobs done: the ceiling is what stops us. This is
        #    the 12:10:43 sample (load1 19.41, 14 runnable on 8 cpus).
        ("load1 19.41 on 8 cpus -> inconclusive", "inconclusive", 1,
         wait_args(tmp, loadavg_file=hot_path), ["completed"],
         dict(asserts=[(lambda p: "load1" in " ".join(p["last_reasons"]),
                        lambda p: p["last_reasons"]),
                       (lambda p: p["runner_loadavg_start"] == 19.41,
                        lambda p: p["runner_loadavg_start"]),
                       (lambda p: p["runner_loadavg_end"] == 19.41,
                        lambda p: p["runner_loadavg_end"])])),
        # 4. The streak must be *consecutive*: a host that goes quiet, spikes, then
        #    settles has to start over. Loads mirror the observed samples.
        ("streak resets when the host spikes again", "quiet", 0,
         wait_args(tmp, stability_samples=3), ["completed"],
         dict(host=ScriptedHost([5.4, 5.4, 19.4, 5.4, 5.4, 5.4]),
              asserts=[(lambda p: p["not_quiet_polls"] == 1,
                        lambda p: p["not_quiet_polls"]),
                       (lambda p: p["runner_loadavg_start"] == 5.4,
                        lambda p: p["runner_loadavg_start"])])),
        # 4b. ... and a host that never holds still for `stability` polls in a row
        #     is inconclusive rather than lucky.
        ("never three quiet in a row -> inconclusive", "inconclusive", 1,
         wait_args(tmp, stability_samples=3), ["completed"],
         dict(host=ScriptedHost([5.4, 5.4, 19.4]),
              asserts=[(lambda p: p["not_quiet_polls"] >= 1,
                        lambda p: p["not_quiet_polls"])])),
        # 5. The permission mishap: 403 is permanent, so we gate on the host alone
        #    and record the blind spot instead of redding a required check.
        ("job list 403 -> host-only, quiet, and labelled", "quiet", 0,
         wait_args(tmp), ["403"],
         dict(asserts=[(lambda p: p["job_list"].startswith("unavailable: HTTP 403"),
                        lambda p: p["job_list"])])),
        # 6. A transient 500 is not permanent: the streak waits for good reads, so
        #    the job list still gates as soon as the endpoint recovers.
        ("job list 500 then recovers", "quiet", 0,
         wait_args(tmp), ["500", "completed", "completed"],
         dict(asserts=[(lambda p: p["job_list"] == "ok", lambda p: p["job_list"]),
                       (lambda p: p["not_quiet_polls"] == 1,
                        lambda p: "not_quiet_polls=%s" % p["not_quiet_polls"]),
                       (lambda p: any("temporarily unavailable" in " ".join(r["reasons"])
                                      for r in p["poll_log"]),
                        lambda p: p["poll_log"]),
                       (lambda p: p["nonlane_jobs_in_flight_at_grant"] == [],
                        lambda p: p["nonlane_jobs_in_flight_at_grant"])])),
        # 7. An unreadable load average must never read as quiet.
        ("loadavg unreadable -> inconclusive", "inconclusive", 1,
         wait_args(tmp, loadavg_file=os.path.join(tmp, "nope")), ["completed"],
         dict(asserts=[(lambda p: "unreadable" in " ".join(p["last_reasons"]),
                        lambda p: p["last_reasons"])])),
        # 8. A ceiling tight enough that nothing passes proves the knob is wired.
        ("loadavg 5.38 over a 1-core ceiling -> inconclusive", "inconclusive", 1,
         wait_args(tmp, loadavg_ceiling=1.0), ["completed"],
         dict(asserts=[(lambda p: p["loadavg_ceiling"] == 1.0,
                        lambda p: p["loadavg_ceiling"])])),
    ]

    for spec in cases:
        name, ok, got, payload = case(*spec)
        print("ok   %s" % name if ok else
              "FAIL %s: expected verdict/code %s, got %s" % (name, spec[1:3], got))
        if not ok:
            failed += 1

    # 9. pgrep-shaped foreign builder: injectable, because a container with no
    #    foreign processes cannot prove the branch.

    def fake_pgrep_builder(*a):
        class R:
            stdout = "4242 /usr/local/cargo/bin/cargo build --release"
            returncode = 0
        return R()

    import subprocess as _sp
    real_run = _sp.run
    setattr(_sp, "run", lambda *a, **k: fake_pgrep_builder())
    try:
        builders = foreign_builders(pgrep="pgrep-fake", mine={1})
    finally:
        _sp.run = real_run
    ok = builders == ["/usr/local/cargo/bin/cargo build --release"]
    print("ok   foreign builder command line parsed" if ok else
          "FAIL foreign builder command line parsed: %s" % builders)
    failed += 0 if ok else 1

    # 10. `quiet_reasons` on an empty `in_flight` must not mention jobs, and a
    #     `None` (blind) list must not either -- but the payload records it.
    snap = {"load1": 1.0, "cpu_used_pct": 10.0, "builders": []}
    ok = (quiet_reasons(snap, [], 8.0, None) == [] and
          quiet_reasons(snap, None, 8.0, None) == [] and
          quiet_reasons(snap, [{"name": "rust", "status": "queued"}], 8.0, None) != [])
    print("ok   quiet_reasons: queued counts, empty/None does not" if ok else
          "FAIL quiet_reasons: %s" % ok)
    failed += 0 if ok else 1

    # 11. The real HTTP path (URL, headers, token) against an in-process server.
    ok, detail = http_server_selftest()
    print("ok   JobList drives the real endpoint: %s" % detail if ok else
          "FAIL JobList real endpoint: %s" % detail)
    failed += 0 if ok else 1

    # 12. correlate: the red2 shape -- two over-SLA buckets that sat in the same
    #     window as a load spike, one green bucket that did not.
    report = {"latency_timeline": [
        {"start_ms": 0, "p99_ms": 22.0, "over_sla": 0},
        {"start_ms": 5000, "p99_ms": 820.0, "over_sla": 9},
        {"start_ms": 10000, "p99_ms": 51.0, "over_sla": 1}]}
    samples_path = os.path.join(tmp, "samples.tsv")
    with open(samples_path, "w") as fh:
        fh.write(SAMPLE_HEADER + "\n")
        for i, (load1, running, used) in enumerate([(5.0, 1, 40.0), (19.4, 14, 99.0),
                                                    (6.0, 2, 50.0)]):
            fh.write("%d\t%.1f\t%.2f\t4.00\t%d\t1038\t%.1f\t1.0\t9\n" % (
                2000 + i * 5, i * 5, load1, running, used))
    rows = correlate(report, read_samples(samples_path), 2000, 5000)
    ok = (len(rows) == 3 and rows[1]["over_sla"] == 9 and rows[1]["host_load1_max"] == 19.4
          and rows[1]["host_running_max"] == 14.0 and rows[0]["over_sla"] == 0)
    print("ok   correlate joins latency buckets to host windows" if ok else
          "FAIL correlate: %s" % rows)
    failed += 0 if ok else 1

    corr_args = argparse.Namespace(report=os.path.join(tmp, "report.json"),
                             samples=samples_path, t0_epoch=2000, t0_file=None,
                             out=os.path.join(tmp, "host-vs-latency.md"),
                             summary_file=os.path.join(tmp, "corr.md"),
                             bucket_ms=5000, contention_pct=80.0, cores=8,
                             quiet_host_file="", stage="self-test")
    with open(os.path.join(tmp, "report.json"), "w") as fh:
        json.dump(report, fh)
    code = cmd_correlate(corr_args)
    text = open(corr_args.out).read()
    ok = code == 0 and "over-SLA bucket(s) coincide with host" in text
    print("ok   correlate names contention as the cause of the tail" if ok else
          "FAIL correlate attribution: %s" % text)
    failed += 0 if ok else 1

    # 13. A green report with no over-SLA bucket must not be called contention.
    with open(os.path.join(tmp, "green.json"), "w") as fh:
        json.dump({"latency_timeline": [{"start_ms": 0, "p99_ms": 22.0, "over_sla": 0}]}, fh)
    corr_args.report = os.path.join(tmp, "green.json")
    corr_args.out = os.path.join(tmp, "green-vs-latency.md")
    code = cmd_correlate(corr_args)
    text = open(corr_args.out).read()
    ok = code == 0 and "No latency bucket missed the SLA" in text and \
        "nothing to attribute" in text
    print("ok   correlate leaves a green run alone" if ok else
          "FAIL correlate green: %s" % text)
    failed += 0 if ok else 1

    # 14. Missing samples must not look like a clean host, and must not gate.
    corr_args.samples = os.path.join(tmp, "nothing.tsv")
    corr_args.out = os.path.join(tmp, "none.md")
    code = cmd_correlate(corr_args)
    ok = code == 0
    print("ok   correlate is non-fatal with no samples" if ok else
          "FAIL correlate no-samples: exit %s" % code)
    failed += 0 if ok else 1

    # 15. The gate's verdict travels with the tail it explains, through the
    #     parser. OBI-403's sibling asked for `lane_wait_seconds` next to the
    #     attribution table: a green run that waited 40 s and a green run that
    #     measured over a saturated host are not the same fact, and today the
    #     reader has to open quiet-host.json to tell them apart.
    quiet_record = os.path.join(tmp, "quiet-host.json")
    with open(quiet_record, "w") as fh:
        json.dump({"schema": 1, "stage": "self-test", "verdict": "quiet",
                   "lane_wait_seconds": 41.7, "runner_loadavg_end": 5.38,
                   "loadavg_ceiling": 8.0, "runner_cores": 8, "job_list": "ok",
                   "job_list_polls": 5}, fh)
    corr_out = os.path.join(tmp, "with-quiet.md")
    buffer = io.StringIO()
    code = None
    text = ""
    try:
        with contextlib.redirect_stdout(buffer):
            code = main(["ci-wait-quiet-lane.py", "correlate",
                         "--report", os.path.join(tmp, "report.json"),
                         "--samples", samples_path, "--t0-epoch", "2000",
                         "--quiet-host-file", quiet_record, "--out", corr_out,
                         "--summary-file", os.path.join(tmp, "quiet-corr.md")])
        text = open(corr_out).read()
        ok = (code == 0 and "| lane_wait_seconds | 41.70 |" in text
              and "over-SLA bucket(s) coincide with host" in text)
        detail = "code=%s" % code
    except Exception as exc:                                  # noqa: BLE001
        ok, detail = False, "raised %s: %s" % (type(exc).__name__, exc)
    print("ok   correlate prints the gate's lane_wait next to the tail" if ok else
          "FAIL correlate lane_wait: %s %s" % (detail, text if not ok else ""))
    failed += 0 if ok else 1

    # 16. `sample` driven through the *parser*, not a hand-built Namespace. The
    #     first version of this check called cmd_sample directly with a Namespace
    #     assembled in the test, and it passed while the shipped `sample` mode
    #     crashed: cmd_sample read `args.psi_file`, which `build_parser` never
    #     defined. In CI that is silent -- the sampler is backgrounded and its
    #     death is swallowed by the `kill`/`wait` in the evidence tail, so the
    #     gate would have recorded a host it never sampled and correlate would
    #     have printed "no host samples recorded" on every run. Anything that
    #     reads an argparse attribute must be constructed by argparse.
    stat_path = os.path.join(tmp, "stat")
    with open(stat_path, "w") as fh:
        fh.write("cpu  100 20 30 800 10 5 7 0 0 0\nprocs_running 3\nprocs_blocked 0\n")
    psi_path = os.path.join(tmp, "pressure")
    with open(psi_path, "w") as fh:
        fh.write("some avg10:0.00 avg60:1.15 total 98765\nfull avg10:0.00 total 0\n")
    sample_out = os.path.join(tmp, "host-samples.tsv")
    argv = ["sample", "--out", sample_out, "--interval-secs", "0.01",
            "--max-secs", "0", "--loadavg-file", quiet_path,
            "--stat-file", stat_path, "--psi-file", psi_path]
    buffer = io.StringIO()
    code = None
    try:
        with contextlib.redirect_stdout(buffer):
            code = main(["ci-wait-quiet-lane.py"] + argv)
        rows = read_samples(sample_out)
        header_ok = open(sample_out).readline().startswith("# epoch")
        ok = (code == 0 and header_ok and len(rows) == 1 and
              rows[0]["load1"] == 5.38 and rows[0]["procs_running"] == 3.0)
        detail = "code=%s header=%s rows=%s" % (code, header_ok, rows)
    except Exception as exc:                                  # noqa: BLE001
        ok, detail = False, "raised %s: %s" % (type(exc).__name__, exc)
    print("ok   sample writes host rows through the CLI" if ok else
          "FAIL sample writes host rows through the CLI: %s" % detail)
    failed += 0 if ok else 1

    print("ci-wait-quiet-lane self-test: %d cases, %d failure(s)" % (
        len(cases) + 8, failed))
    return 1 if failed else 0


# ----------------------------------------------------------------- cli ----

def build_parser():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true",
                        help="run the built-in cases and exit")
    sub = parser.add_subparsers(dest="mode")

    def common(p):
        p.add_argument("--loadavg-file", default=LOADAVG_FILE,
                       help="loadavg-shaped file to read (default /proc/loadavg; "
                            "the self-test and any non-Linux host point this elsewhere)")
        p.add_argument("--stat-file", default=STAT_FILE)
        p.add_argument("--psi-file", default=PSI_FILE,
                       help="pressure-stall file to read (default /proc/pressure/cpu; "
                            "recorded, never gated)")
        p.add_argument("--cores", type=int, default=0,
                       help="override the CPUs visible to the runner (the loadavg "
                            "ceiling is derived from it)")
        p.add_argument("--skip-proc-scan", action="store_true",
                       help="drop the pgrep backstop (a container cannot see foreign "
                            "tenants anyway; the job list is the signal that works)")

    wait = sub.add_parser("wait", help="block until the lane host is quiet")
    common(wait)
    wait.add_argument("--stage", default=os.environ.get("GITHUB_JOB", "lane"),
                      help="label in the artifact and the step summary")
    wait.add_argument("--out", default="results", help="directory for quiet-host.json")
    wait.add_argument("--deadline-secs", type=int, default=900,
                      help="how long the lane may take to get quiet before the run is "
                           "declared inconclusive (a normal `rust` job is 4-6 minutes, "
                           "15m51s worst observed, so 900s is the e1-1 default)")
    wait.add_argument("--interval-secs", type=float, default=10.0)
    wait.add_argument("--stability-samples", type=int, default=3,
                      help="consecutive quiet polls required before measuring")
    wait.add_argument("--loadavg-ceiling", type=float, default=None,
                      help="override the 1-minute load average ceiling "
                           "(default --loadavg-factor x cpus visible)")
    wait.add_argument("--loadavg-factor", type=float, default=1.0,
                      help="ceiling = factor x cpus visible; 1.0 passes the two "
                           "observed green gates (6.20, 5.38 on 8 cpus) and blocks "
                           "the observed saturated host (19.41)")
    wait.add_argument("--cpu-busy-ceiling", type=float, default=None,
                      help="optional CPU utilisation ceiling; recorded but unset by "
                           "default because one day of samples does not calibrate it")
    wait.add_argument("--current-job", default="", help="job name to treat as ours")
    wait.add_argument("--summary-file", default=os.environ.get("GITHUB_STEP_SUMMARY", ""),
                      help="append the table here (default $GITHUB_STEP_SUMMARY)")

    sample = sub.add_parser("sample", help="record host counters while measuring")
    common(sample)
    sample.add_argument("--out", default="results/host-samples.tsv")
    sample.add_argument("--interval-secs", type=float, default=5.0,
                        help="matches the report's 5000 ms latency buckets")
    sample.add_argument("--max-secs", type=int, default=900,
                        help="hard stop; the workflow kills it after the measurement")

    corr = sub.add_parser("correlate", help="join host samples to the report tail")
    corr.add_argument("--report", default="results/ci-e1-1.json")
    corr.add_argument("--quiet-host-file", default="",
                      help="the gate's quiet-host.json; when readable, its verdict and "
                           "lane_wait_seconds are printed next to the tail so a reader "
                           "does not need two artifacts to know if the host was quiet")
    corr.add_argument("--samples", default="results/host-samples.tsv")
    corr.add_argument("--t0-epoch", type=int, default=None)
    corr.add_argument("--t0-file", default="")
    corr.add_argument("--out", default="results/host-vs-latency.md")
    corr.add_argument("--bucket-ms", type=int, default=5000)
    corr.add_argument("--contention-pct", type=float, default=80.0,
                      help="CPU utilisation at or above which a bucket is 'contended'")
    corr.add_argument("--cores", type=int, default=0)
    corr.add_argument("--stage", default=os.environ.get("GITHUB_JOB", "lane"))
    corr.add_argument("--summary-file", default=os.environ.get("GITHUB_STEP_SUMMARY", ""))
    return parser


def main(argv):
    resolve_tools()
    parser = build_parser()
    args = parser.parse_args(argv[1:])
    if args.self_test:
        return self_test()
    if not args.mode:
        parser.error("needs a mode: wait, sample, correlate, or --self-test")
    if args.mode == "wait":
        return cmd_wait(args)
    if args.mode == "sample":
        return cmd_sample(args)
    return cmd_correlate(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
