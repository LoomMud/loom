#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Oberfield
# SPDX-License-Identifier: AGPL-3.0-only
#
# Installs any missing CI tools with apt (OBI-113). GitHub-hosted runners
# already have them all, so there this is a no-op. The ARC scale set
# (`arc-runner-set-loommud`) uses the minimal `actions-runner` image, which
# lacks a C toolchain, psql, python3 and gh.
#
# Usage: scripts/ci-ensure-tools.sh cmd:apt-package [cmd:apt-package ...]
#   e.g. scripts/ci-ensure-tools.sh cc:build-essential psql:postgresql-client
# `gh` is special-cased: it comes from GitHub's apt repo.
set -euo pipefail

missing=()
want_gh=0
for spec in "$@"; do
  cmd=${spec%%:*}
  pkg=${spec#*:}
  if ! command -v "$cmd" >/dev/null 2>&1; then
    if [ "$cmd" = gh ]; then want_gh=1; else missing+=("$pkg"); fi
  fi
done

if [ ${#missing[@]} -eq 0 ] && [ $want_gh -eq 0 ]; then
  echo "ci-ensure-tools: all present"
  exit 0
fi

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"
export DEBIAN_FRONTEND=noninteractive

if [ $want_gh -eq 1 ]; then
  command -v curl >/dev/null 2>&1 || missing+=(curl)
  $SUDO apt-get update -qq
  [ ${#missing[@]} -eq 0 ] || $SUDO apt-get install -y -qq --no-install-recommends "${missing[@]}"
  missing=()
  $SUDO install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    | $SUDO tee /etc/apt/keyrings/githubcli-archive-keyring.gpg >/dev/null
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
    | $SUDO tee /etc/apt/sources.list.d/github-cli.list >/dev/null
  missing+=(gh)
fi

echo "ci-ensure-tools: installing ${missing[*]}"
$SUDO apt-get update -qq
$SUDO apt-get install -y -qq --no-install-recommends "${missing[@]}"
