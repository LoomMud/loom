# CI runners (GitHub-hosted or self-hosted)

Every job in `loom`, `warp` and `loom-gitops` workflows picks its runner
with the same expression (OBI-111):

```yaml
runs-on: ${{ (vars.CI_RUNS_ON && !github.event.pull_request.head.repo.fork) && (startsWith(vars.CI_RUNS_ON, '[') && fromJSON(vars.CI_RUNS_ON) || vars.CI_RUNS_ON) || 'ubuntu-latest' }}
```

## Choosing the runner

Set the **organization-level** Actions variable `CI_RUNS_ON` on `LoomMud`
(Settings → Secrets and variables → Actions → Variables). A repository
variable with the same name overrides the org value for that repo.

| `CI_RUNS_ON` value                     | Result                                   |
|----------------------------------------|------------------------------------------|
| unset / empty                          | `ubuntu-latest` (GitHub-hosted, as before) |
| `self-hosted` (plain text)             | single label                             |
| `["self-hosted","linux","x64"]`        | JSON array: runner must carry all labels |

Plain text is one label. A value starting with `[` is parsed as a JSON
array. Do not wrap a single label in quotes (`"self-hosted"` would be taken
literally, quotes included). A malformed array fails the workflow at
start-up; unset the variable to go back to GitHub-hosted.

**Fork pull requests always run on GitHub-hosted runners**, whatever the
variable says. The repos are public; a fork PR is untrusted code and must
not run on a lab machine. PRs from branches of the repo itself, and pushes
to `main` and tags, use `CI_RUNS_ON`.

## Runner requirements

- Linux x64. The gitleaks, cosign and syft downloads are `linux_x64`/`amd64`.
- Docker available to the runner user. Needed for the `postgres` service
  container (`rust` job), the Docker container actions
  (`EmbarkStudios/cargo-deny-action`, `fsfe/reuse-action`) and
  `docker buildx` in `release-image`.
- `git`, `curl`, `tar`, `bash`, `python3`, a C/C++ toolchain (`gcc`/`g++`
  or `clang`; cargo-fuzz builds libFuzzer), `psql` (`postgresql-client`,
  used to create the CI logins). For `release-image` also `jq` and `gh`.
  GitHub-hosted images ship all of these; self-hosted runners must install
  them.
- Rust is installed by `dtolnay/rust-toolchain` (rustup): stable pinned
  toolchain plus nightly for the two fuzz jobs.
- Disk: budget at least 30 GB free for the Rust target/cache
  (`Swatinem/rust-cache`, three workspaces), the nightly toolchain, and
  Docker images.
- Host ports 5432 (postgres service) and 4000 (`loadtest-smoke`) are bound
  on the runner host. Run one job at a time per host, or use ephemeral
  runners, to avoid clashes.

Prefer **ephemeral** runners (`--ephemeral`, or actions-runner-controller).
Persistent runners keep state between jobs (`/tmp/loom-serve.*`, the
`loom-builder` buildx builder, Docker images, caches). `release-image`
reuses an existing builder and logs out of GHCR at the end, but a crashed
job can still leave `~/.docker/config.json` credentials behind.
