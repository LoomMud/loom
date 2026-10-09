# Agent git identity

Every commit made by an Obiemud agent must be authored, committed and DCO-signed **as that agent**.

This exists because of OBI-373: Gimli's commits on PR #159 were authored and signed as Aragorn — the
shared worktree carried the CTO's `user.name`/`user.email`, and `scripts/check-dco.sh` could not see the
problem because the sign-off was valid, it just belonged to the wrong agent.

## The convention

| Field       | Value                                                     |
|-------------|-----------------------------------------------------------|
| name        | `<Agent> (Oberfield agent)` — the agent's Paperclip name  |
| email       | `<urlKey>@agents.oberfield.invalid`                       |
| author      | that identity                                             |
| committer   | that identity                                             |
| sign-off    | `Signed-off-by: <same name> <same email>` (`git commit -s`) |
| trailer     | `Co-Authored-By: Paperclip <noreply@paperclip.ing>` stays |

`.invalid` is the RFC 2606 reserved TLD: the address can never route and is never a real mailbox, so no
agent identity leaks a person's email into public git history.

Current roster:

| Agent    | Identity                                                            |
|----------|---------------------------------------------------------------------|
| Aragorn  | `Aragorn (Oberfield agent) <aragorn@agents.oberfield.invalid>`      |
| Gimli    | `Gimli (Oberfield agent) <gimli@agents.oberfield.invalid>`          |
| Legolas  | `Legolas (Oberfield agent) <legolas@agents.oberfield.invalid>`      |
| Bilbo    | `Bilbo (Oberfield agent) <bilbo@agents.oberfield.invalid>`          |
| Frodo    | `Frodo (Oberfield agent) <frodo@agents.oberfield.invalid>`          |
| Gandalf  | `Gandalf (Oberfield agent) <gandalf@agents.oberfield.invalid>`      |

OBI-374 proposed `<Agent> (Loom agent) <agent>@agents.loom.invalid`. We use `oberfield` instead of `loom`
because that form is already the shipped convention: measured on `github/main`, **71 commits** are authored
`@agents.oberfield.invalid` (58 carrying the `(Oberfield agent)` display name, 48 with a matching
`Signed-off-by`), so switching domain would split attribution across history. If the board
prefers `agents.loom.invalid`, the change is this table plus one env block per agent.

## Injection mechanism: per run, not per worktree

Identity comes from the four git environment variables set in each agent's Paperclip **adapter env**
(`adapterConfig.env`), which the adapter forwards to the spawned agent process and every tool it runs:

```
GIT_AUTHOR_NAME=<Agent> (Oberfield agent)
GIT_AUTHOR_EMAIL=<agent>@agents.oberfield.invalid
GIT_COMMITTER_NAME=<Agent> (Oberfield agent)
GIT_COMMITTER_EMAIL=<agent>@agents.oberfield.invalid
```

Environment beats config in git's identity resolution, so a stale `user.email` left in a shared worktree
(by whoever ran there last) can no longer end up in a commit. This is the property the CEO asked for in
OBI-374: per-run injection, independent of the workspace. The same `env` object works for the `pi_local`
and `codex_local` adapters.

Never write `user.name`/`user.email` into a worktree or global config as a substitute: workspaces are
shared and get reused across agents, which is exactly how OBI-373 happened.

## Verification (acceptance test)

The OBI-373 leak case, reproduced in a throwaway repo whose worktree config says
`Legolas <legolas@obiemud.local>` and `format.signoff=true` (git 2.47.3):

```sh
$ git var GIT_AUTHOR_IDENT                                     # nothing injected
Legolas <legolas@obiemud.local> 1791528488 +0000               # <- the leak
$ GIT_AUTHOR_NAME="Gimli (Oberfield agent)" GIT_AUTHOR_EMAIL=gimli@agents.oberfield.invalid \
  GIT_COMMITTER_NAME="Gimli (Oberfield agent)" GIT_COMMITTER_EMAIL=gimli@agents.oberfield.invalid \
  sh -c 'git var GIT_AUTHOR_IDENT; git var GIT_COMMITTER_IDENT; git commit -q -s -m "check: identity"'
Gimli (Oberfield agent) <gimli@agents.oberfield.invalid> 1791528488 +0000
Gimli (Oberfield agent) <gimli@agents.oberfield.invalid> 1791528488 +0000
author=Gimli (Oberfield agent) <gimli@agents.oberfield.invalid>
committer=Gimli (Oberfield agent) <gimli@agents.oberfield.invalid>
Signed-off-by: Gimli (Oberfield agent) <gimli@agents.oberfield.invalid>
```

In a fresh agent run, in **any** workspace — including one that has another agent's `user.email` set:

```sh
git var GIT_AUTHOR_IDENT
git var GIT_COMMITTER_IDENT
```

Both must print this agent's own identity. Then make a throwaway commit in a scratch repo and confirm the
DCO gate passes on it:

```sh
git commit -q -s -m "check: identity"
```

`Signed-off-by:` must equal the author line. The same precedence holds when a workspace has no local `user.*`
at all and would fall through to the container-wide `test <test@test.com>`: re-checked in the shared `loom`
checkout, `git var` still prints the injected identity. `scripts/check-dco.sh` passes on the result.

## Rules for agents

1. **Do not set `user.name`/`user.email` anywhere** (worktree, global, or `-c` on a permanent basis).
   Your identity is your run env.
2. **Interim rule until every agent's adapter env is applied** (OBI-374): before the first commit of a
   run, check `git var GIT_AUTHOR_IDENT` / `git var GIT_COMMITTER_IDENT`. If it is not your own identity,
   export the four `GIT_*` variables for your session from the table above. If you cannot, pass them per
   command:
   `git -c user.name="Gimli (Oberfield agent)" -c user.email="gimli@agents.oberfield.invalid" commit -s …`
   and say so in the task comment.
3. If a commit fails with *"Please tell me who you are"*, that is the guard working. Do not paper over it
   with someone else's identity or a generic bot address — fix your own env.
4. **Always pass `-s`.** Setting `format.signOff=true` in repo config does *not* sign commits (it belongs
   to `git format-patch`; verified no-op for `git commit` on 2.47.3), yet several shared workspaces still
   carry it. A missing trailer is caught by `scripts/check-dco.sh` and fails the `dco` CI job.
5. `scripts/check-dco.sh` proves the trailer matches the author; it cannot prove the author is the right
   agent. Identity injection is what closes that gap.
6. The same rule applies to GitHub: reviews/approvals go through the `loom-reviewer` app, never through
   the board's `gh` login (OBI-142).

## Hiring checklist (new agents)

Add at creation, before the agent's first run:

- [ ] `adapterConfig.env` contains the four `GIT_*` keys with the new agent's own identity.
- [ ] Name/email follow the convention table above (`<urlKey>@agents.oberfield.invalid`).
- [ ] No `user.*` in any workspace config for this agent.
- [ ] First run verifies `git var GIT_AUTHOR_IDENT` / `git var GIT_COMMITTER_IDENT` and pastes the output
      in the onboarding issue.
- [ ] Agent instructions repeat the interim rule (item 2 above) until cleanup below is finished.

Only a board-authenticated caller — or an agent holding `agents:configure` / `agents:suggest-changes` —
can write another agent's adapter env.

## Cleanup still outstanding

Once every agent's run env carries its identity, remove the stale fallbacks so a misconfigured run fails
loudly instead of inheriting someone else's name. This is not theoretical: **19 commits on `main` are authored
`test <test@test.com>`** — the container-wide fallback has already reached published history (`a228684`,
`f0db414`, `d155acd`, …), next to 195 `@obiemud.local` and 40 `@loommud.dev` pre-convention addresses:

- `user.name`/`user.email` in `/paperclip/.gitconfig` (currently `test <test@test.com>`, shared by every
  agent in the container),
- `user.name`/`user.email` in the worktree configs under the shared agent workspace
  (`…/_default/*/.git/config`). Audited on 2026-10-09: 11 of them set an identity. `aragorn-loom` is
  configured as **Gimli** — a foreign identity sitting in the CTO's own checkout, the OBI-373 shape;
  `gimli-loom` and the `legolas-*` trees carry pre-convention addresses (`@obiemud.local`, `@obiemud.dev`,
  `@loommud.dev`); `aragorn-loom-gitops`, `aragorn-loom-s4`, `aragorn-warp`, `loom-gitops` and `warp` already
  hold the convention form. The shared `loom` checkout sets no local `user.*` and falls through to
  `test <test@test.com>`.
- `format.signoff=true` in 5 of those worktree configs: harmless, but it teaches the wrong rule — it does not
  sign commits (see *Rules for agents* above).

Tracked on OBI-374; deliberately sequenced **after** env injection lands for all agents.
