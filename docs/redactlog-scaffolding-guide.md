# Redactlog scaffolding guide

This guide walks you through setting up the entire `redactlog` project structure, toolchain, CI, and configuration files **before** inviting Claude Code into the repo. The goal is to maximize Claude Code's token budget for actual implementation work rather than boilerplate.

By the end of this guide you will have:

- A git repo with the complete module layout from the architecture doc
- `go.mod` declaring Go 1.23+ with the right dependencies
- All required developer tools installed locally
- `.golangci.yml`, `.github/workflows/*.yml`, and supporting configs
- `CLAUDE.md`, `docs/` (ADRs, architecture, roadmap), and placeholder package files
- A first commit and an optional `v0.0.1` tag to verify module proxy resolution

**Estimated time**: 60–90 minutes if you follow top to bottom.

---

## Table of contents

1. [Prerequisites](#1-prerequisites)
2. [Install developer toolchain](#2-install-developer-toolchain)
3. [Create the repository](#3-create-the-repository)
4. [Initialize the Go module](#4-initialize-the-go-module)
5. [Create the directory structure](#5-create-the-directory-structure)
6. [Create placeholder Go files](#6-create-placeholder-go-files)
7. [Add dependencies](#7-add-dependencies)
8. [Write configuration files](#8-write-configuration-files)
9. [Write CI workflows](#9-write-ci-workflows)
10. [Drop in the docs](#10-drop-in-the-docs)
11. [First commit and tag](#11-first-commit-and-tag)
12. [Verification checklist](#12-verification-checklist)
13. [Invoke Claude Code](#13-invoke-claude-code)

---

## 1. Prerequisites

Before starting, confirm you have:

| Requirement | Version | Verify |
|---|---|---|
| Go | 1.23 or newer | `go version` |
| Git | any recent | `git --version` |
| A GitHub account | — | — |
| A GitHub repo created at `github.com/JAS0N-SMITH/redactlog` | empty | — |

**Installing Go**: if you don't have 1.23+, download from [go.dev/dl](https://go.dev/dl/). Gin v1.12+ and recent slog tooling require 1.23 as a floor.

**Setting up the GitHub repo**: create it empty (no README, no license, no .gitignore — we'll add those ourselves). If you don't own the `redactlog` org on GitHub, use `github.com/<your-handle>/redactlog` instead and globally replace `redactlog/redactlog` with your path in all examples below.

---

## 2. Install developer toolchain

You need four developer tools beyond Go itself:

### 2.1 golangci-lint v2

The lint aggregator. Current stable is v2.x; v1 config files are incompatible and should not be used for new projects. Source: [golangci-lint.run install docs](https://golangci-lint.run/docs/welcome/install/local/).

**Recommended**: install the official binary (the Go team's documentation advises against `go install` because it compiles locally against your Go version and is not guaranteed to work).

```bash
# Linux / macOS — installs to $(go env GOPATH)/bin
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $(go env GOPATH)/bin v2.11.4
```

**macOS alternative** via Homebrew (note: Homebrew may build against a different Go version):

```bash
brew install golangci-lint
```

Verify:

```bash
golangci-lint --version
# expected: golangci-lint has version v2.11.x ...
```

Pin the exact version you installed — we'll reference it in CI.

### 2.2 govulncheck

Go's official vulnerability scanner, maintained by the Go security team. Source: [go.dev/doc/security/vuln](https://go.dev/doc/security/vuln/).

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
```

Verify:

```bash
govulncheck -version
```

### 2.3 gofumpt and goimports

`gofumpt` is a stricter superset of `gofmt`; `goimports` handles import grouping. `golangci-lint` can run both in its `fmt` subcommand, so this install is optional — only needed if you want to run them standalone.

```bash
go install mvdan.cc/gofumpt@latest
go install golang.org/x/tools/cmd/goimports@latest
```

### 2.4 pkgsite (optional, for local godoc preview)

Lets you preview how your package will render on `pkg.go.dev` before tagging.

```bash
go install golang.org/x/pkgsite/cmd/pkgsite@latest
```

Then run `pkgsite -http :6060` from the repo root; browse to [localhost:6060](http://localhost:6060).

### 2.5 Verify your PATH

All `go install` binaries land in `$(go env GOPATH)/bin`. Make sure that directory is on your `PATH`:

```bash
echo $PATH | tr ':' '\n' | grep -q "$(go env GOPATH)/bin" && echo "PATH ok" || echo "ADD $(go env GOPATH)/bin to PATH"
```

If missing, add `export PATH="$(go env GOPATH)/bin:$PATH"` to your shell rc file.

---

## 3. Create the repository

```bash
# Clone the empty GitHub repo you created
git clone git@github.com:redactlog/redactlog.git
cd redactlog

# Or if you're using your own handle:
# git clone git@github.com:<your-handle>/redactlog.git
```

Set up your git identity locally if not already global:

```bash
git config user.name "Your Name"
git config user.email "you@example.com"
```

If you plan to sign tags (recommended for v1.0.0), verify your GPG or SSH signing key is configured:

```bash
git config user.signingkey <key-id>
git config commit.gpgsign true
git config tag.gpgsign true
```

---

## 4. Initialize the Go module

```bash
go mod init github.com/JAS0N-SMITH/redactlog
```

Then pin the Go version. Open the generated `go.mod` and replace its content:

```go
module github.com/JAS0N-SMITH/redactlog

go 1.25.9
```

The minimum is 1.25.9 — Gin v1.12 and its transitive deps require at least go1.25, and 1.25.9 is the first patch that clears all known standard library vulnerabilities. Do not specify a `toolchain` directive.

---

## 5. Create the directory structure

Run this single block to create the full layout per architecture doc §2:

```bash
# Top-level subpackages
mkdir -p redact httpmw gin

# Internal helpers
mkdir -p internal/bufpool internal/canonheader internal/luhn internal/ringbuf

# Docs
mkdir -p docs

# Benchmarks as a separate module
mkdir -p bench

# Examples
mkdir -p examples/nethttp examples/gin

# Testdata roots
mkdir -p testdata/fuzz testdata/golden

# GitHub scaffolding
mkdir -p .github/workflows .github/ISSUE_TEMPLATE
```

Verify:

```bash
tree -L 2
# Should list: redact, httpmw, gin, internal, docs, bench, examples, testdata, .github
```

(If you don't have `tree`, `find . -maxdepth 2 -type d | sort` works.)

---

## 6. Create placeholder Go files

Every Go package directory needs at least one `.go` file to be a valid package. Create `doc.go` files that `go build` can compile and that give Claude Code the correct package comments to extend.

### 6.1 Root package doc

```bash
cat > doc.go <<'EOF'
// Package redactlog provides redaction-first HTTP logging middleware
// for Go services in regulated industries.
//
// See docs/architecture.md and the ADRs under docs/ for the full design.
// See CLAUDE.md for contribution conventions.
package redactlog
EOF
```

### 6.2 Subpackage docs

```bash
cat > redact/doc.go <<'EOF'
// Package redact implements the compile-once Pino-style redaction engine
// used by redactlog. It is usable standalone for non-HTTP redaction needs.
//
// See docs/ADR-002-path-dsl.md for DSL design rationale.
package redact
EOF

cat > httpmw/doc.go <<'EOF'
// Package httpmw provides framework-agnostic net/http middleware that
// captures request and response metadata and bodies, applying a redactor
// before emission.
//
// See docs/ADR-003-httpsnoop-dependency.md for response-writer handling.
package httpmw
EOF

cat > gin/doc.go <<'EOF'
// Package gin adapts redactlog's http.Handler middleware to gin.HandlerFunc.
// This is the only package in the module that imports gin-gonic/gin.
//
// See docs/ADR-004-dedicated-gin-subpackage.md for the adapter rationale.
package gin
EOF
```

### 6.3 Internal package docs

```bash
cat > internal/bufpool/doc.go <<'EOF'
// Package bufpool provides a sync.Pool-backed bytes.Buffer pool used by
// the redactor and middleware for allocation-free hot paths.
package bufpool
EOF

cat > internal/canonheader/doc.go <<'EOF'
// Package canonheader normalizes HTTP header names for deny-list matching.
package canonheader
EOF

cat > internal/luhn/doc.go <<'EOF'
// Package luhn implements the Luhn checksum algorithm used by the PAN
// detector in the PCI preset.
package luhn
EOF

cat > internal/ringbuf/doc.go <<'EOF'
// Package ringbuf is a v2 placeholder. v1 uses head-truncation for body
// capture per ADR-006; do not wire this package into v1.
package ringbuf
EOF
```

### 6.4 Bench module

The `bench/` directory is its own module so benchmark deps don't pollute `go.mod`:

```bash
cd bench
go mod init github.com/JAS0N-SMITH/redactlog/bench

cat > doc.go <<'EOF'
// Package bench contains comparative benchmarks against zap, zerolog, and
// samber/slog-gin. This is a separate Go module to keep benchmark-only
// dependencies out of the main go.mod.
package bench
EOF

cd ..
```

### 6.5 Verify everything compiles

```bash
go build ./...
# no output = success
```

---

## 7. Add dependencies

Add the three third-party direct dependencies from the architecture doc. Sources: [felixge/httpsnoop](https://pkg.go.dev/github.com/felixge/httpsnoop), [otel semconv](https://pkg.go.dev/go.opentelemetry.io/otel/semconv/v1.26.0), [gin-gonic/gin](https://pkg.go.dev/github.com/gin-gonic/gin).

```bash
# httpsnoop — used by httpmw for ResponseWriter capture
go get github.com/felixge/httpsnoop@latest

# OpenTelemetry semantic conventions v1.26.0 (pinned per architecture doc)
go get go.opentelemetry.io/otel/semconv/v1.26.0

# Gin — used only by the gin/ subpackage
go get github.com/gin-gonic/gin@latest
```

Add imports to the placeholder docs so `go mod tidy` keeps them:

```bash
# Temporary import-only stubs so go mod tidy retains the deps.
# Claude Code will replace these during implementation.

cat > httpmw/deps_stub.go <<'EOF'
package httpmw

import (
	_ "github.com/felixge/httpsnoop"
	_ "go.opentelemetry.io/otel/semconv/v1.26.0"
)
EOF

cat > gin/deps_stub.go <<'EOF'
package gin

import (
	_ "github.com/gin-gonic/gin"
)
EOF
```

Now tidy:

```bash
go mod tidy
```

Your `go.mod` should now list all three as direct deps. Your `go.sum` will have content. Verify:

```bash
go mod graph | head -20
go build ./...
```

---

## 8. Write configuration files

### 8.1 LICENSE

Apache 2.0 per the architecture doc. Download the official text:

```bash
curl -sSL https://www.apache.org/licenses/LICENSE-2.0.txt > LICENSE
```

Or grab the standard GitHub template from the web UI when creating the repo.

### 8.2 .gitignore

```bash
cat > .gitignore <<'EOF'
# Binaries
*.test
*.out

# Editor
.idea/
.vscode/
*.swp
*~

# Build cache
/dist/
/bin/

# Coverage
coverage.out
coverage.html

# Fuzz caches (we commit seed corpora only)
testdata/fuzz/**/.fuzz-cache/

# OS
.DS_Store
Thumbs.db

# Local env
.env
.envrc
EOF
```

### 8.3 .editorconfig

```bash
cat > .editorconfig <<'EOF'
root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true

[*.go]
indent_style = tab
indent_size = 4

[*.{yml,yaml,md}]
indent_style = space
indent_size = 2

[Makefile]
indent_style = tab
EOF
```

### 8.4 .golangci.yml (v2 format)

The v2 config schema is incompatible with v1. Source: [golangci-lint v2 announcement](https://ldez.github.io/blog/2025/03/23/golangci-lint-v2/).

```bash
cat > .golangci.yml <<'EOF'
version: "2"

run:
  timeout: 5m
  go: "1.23"

linters:
  default: none
  enable:
    - errcheck
    - govet
    - staticcheck
    - revive
    - gosec
    - unused
    - ineffassign
    - gocritic
    - misspell
    - unparam
    - prealloc
    - bodyclose
    - noctx
    - errorlint
    - gocyclo
    - godot

  settings:
    gocyclo:
      min-complexity: 15
    revive:
      rules:
        - name: exported
          severity: warning
          disabled: false
    gosec:
      excludes:
        - G115  # integer conversion overflow (noisy on HTTP size fields)

  exclusions:
    warn-unused: true
    presets:
      - comments
      - std-error-handling
      - common-false-positives

formatters:
  enable:
    - gofumpt
    - goimports
  settings:
    goimports:
      local-prefixes:
        - github.com/JAS0N-SMITH/redactlog
EOF
```

Verify:

```bash
golangci-lint run
# Should produce no output (no Go files yet besides stubs and doc comments).
```

### 8.5 SECURITY.md

Security reporting policy — required by responsible disclosure norms and GitHub's private vulnerability reporting feature.

```bash
cat > SECURITY.md <<'EOF'
# Security policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.x     | ✅        |
| < 1.0   | ❌        |

## Reporting a vulnerability

Please do **not** file public GitHub issues for security problems.

Use GitHub's private vulnerability reporting (Security tab → Report a vulnerability)
or email `security@<TODO>`.

You should receive a response within 48 hours. A confirmed fix will be published
within 14 days of confirmation, coordinated with you for disclosure.

## Out of scope

- Bugs in example code under `examples/`
- Missing redaction in user-supplied configurations outside the shipped presets
EOF
```

Replace `<TODO>` with your actual email before first tag.

### 8.6 CHANGELOG.md

```bash
cat > CHANGELOG.md <<'EOF'
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial project scaffolding.
EOF
```

### 8.7 README.md

A placeholder README. Claude Code will replace this during M9 (docs milestone).

```bash
cat > README.md <<'EOF'
# redactlog

> Redaction-first HTTP logging middleware for Go services in regulated industries.

**Status**: under active development (pre-v1.0.0). Do not use in production yet.

See:

- [docs/architecture.md](docs/architecture.md) — full v1 architecture
- [docs/roadmap.md](docs/roadmap.md) — 12-week solo shipping plan
- [docs/](docs/) — ADRs 001–008
- [CLAUDE.md](CLAUDE.md) — contribution conventions (human and agent)

## Quick start

Coming in M9.

## License

Apache 2.0 — see [LICENSE](LICENSE).
EOF
```

---

## 9. Write CI workflows

Three workflows: lint+test on every PR, fuzz-short on every PR, benchmarks on main pushes only. Sources: [setup-go docs](https://github.com/actions/setup-go), [GitHub Actions Go guide](https://docs.github.com/actions/automating-builds-and-tests/building-and-testing-go).

Note: `setup-go@v5` includes build and module caching by default; `setup-go@v6` is the newest major and also supported. Pinning to `v5` for stability in this scaffold.

### 9.1 Primary CI

```bash
cat > .github/workflows/ci.yml <<'EOF'
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  lint:
    name: Lint
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: "1.23"
          cache: true

      - name: Install golangci-lint
        run: |
          curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh \
            | sh -s -- -b $(go env GOPATH)/bin v2.11.4

      - run: golangci-lint run

  test:
    name: Test (Go ${{ matrix.go }} / ${{ matrix.os }})
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest]
        go: ["1.23", "1.24"]
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: ${{ matrix.go }}
          cache: true

      - run: go vet ./...
      - run: go test -race -coverprofile=coverage.out ./...

      - name: Coverage summary
        if: matrix.os == 'ubuntu-latest' && matrix.go == '1.23'
        run: go tool cover -func=coverage.out | tail -1

  vuln:
    name: govulncheck
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: "1.23"
          cache: true

      - name: Install govulncheck
        run: go install golang.org/x/vuln/cmd/govulncheck@latest

      - run: govulncheck ./...
EOF
```

### 9.2 Fuzz workflow

```bash
cat > .github/workflows/fuzz.yml <<'EOF'
name: Fuzz

on:
  pull_request:
    branches: [main]
  schedule:
    - cron: "0 6 * * *"  # daily 06:00 UTC

permissions:
  contents: read

jobs:
  fuzz:
    name: Fuzz (${{ matrix.target }})
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        # Add fuzz targets here as you create them.
        # Example entries Claude Code will populate:
        # - { pkg: "./redact", target: "FuzzRedactWalk", time: "60s" }
        include:
          - pkg: "./..."
            target: ""
            time: "10s"
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: "1.23"
          cache: true

      - name: Run short fuzz
        if: matrix.target == ''
        run: go test -run=^$ -short ./...

      - name: Run fuzz target
        if: matrix.target != ''
        run: |
          TIME=${{ matrix.time }}
          if [ "${{ github.event_name }}" = "schedule" ]; then
            TIME=10m
          fi
          go test -run=^$ -fuzz=^${{ matrix.target }}$ -fuzztime=$TIME ${{ matrix.pkg }}
EOF
```

### 9.3 Benchmarks workflow (main only)

```bash
cat > .github/workflows/bench.yml <<'EOF'
name: Benchmarks

on:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  bench:
    name: Run benchmarks
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: "1.23"
          cache: true

      - name: Benchmarks (main module)
        run: go test -run=^$ -bench=. -benchmem -count=5 ./... | tee bench-main.txt

      - name: Benchmarks (bench module)
        working-directory: ./bench
        run: go test -run=^$ -bench=. -benchmem -count=5 ./... | tee ../bench-comparative.txt

      - uses: actions/upload-artifact@v4
        with:
          name: benchmark-results
          path: |
            bench-main.txt
            bench-comparative.txt
          retention-days: 90
EOF
```

### 9.4 Dependabot

```bash
cat > .github/dependabot.yml <<'EOF'
version: 2
updates:
  - package-ecosystem: gomod
    directory: "/"
    schedule:
      interval: weekly
    open-pull-requests-limit: 5
    commit-message:
      prefix: "chore(deps)"

  - package-ecosystem: gomod
    directory: "/bench"
    schedule:
      interval: monthly
    open-pull-requests-limit: 3
    commit-message:
      prefix: "chore(deps,bench)"

  - package-ecosystem: github-actions
    directory: "/"
    schedule:
      interval: monthly
    commit-message:
      prefix: "chore(ci)"
EOF
```

### 9.5 Issue template (optional but tidy)

```bash
cat > .github/ISSUE_TEMPLATE/bug_report.md <<'EOF'
---
name: Bug report
about: Something behaving incorrectly
labels: bug
---

**Version**: (output of `go list -m github.com/JAS0N-SMITH/redactlog`)

**What happened**:

**What you expected**:

**Minimal reproduction** (Go code or steps):
EOF

cat > .github/ISSUE_TEMPLATE/feature_request.md <<'EOF'
---
name: Feature request
about: Ideas for v2 or later
labels: v2
---

**Motivation**:

**Proposed API** (if any):

**Alternatives considered**:

> Note: v1 scope is frozen per docs/architecture.md. New features land in v2
> unless they fix a correctness or security bug.
EOF
```

---

## 10. Drop in the docs

Copy the four documents you've already produced into `docs/`.

```bash
# From the repo root:
# You already have these as artifacts from earlier in the project.
# Save each one from the Claude conversation into docs/:
#
# - docs/architecture.md          ← the v1 architecture doc
# - docs/roadmap.md               ← the 12-week roadmap
# - docs/gap-analysis.md          ← ecosystem gap analysis (optional, useful context)
# - docs/research.md              ← deep research notes (optional)
# - CLAUDE.md (repo root, not docs/)
```

Then split the architecture doc's §14 into eight separate ADR files. The shape of each file:

```bash
cat > docs/ADR-001-slog-handler-wrapper.md <<'EOF'
# ADR-001: slog.Handler wrapper

**Status**: Accepted
**Date**: <today>

## Context

<copy ADR-001 section from architecture doc>

## Decision

slog.Handler wrapper, not ReplaceAttr-only.

## Consequences

<copy consequences from architecture doc>
EOF
```

Repeat for ADR-002 through ADR-008. Keeping each ADR in its own file means:

- You can supersede one without editing others.
- Claude Code can reference them surgically by filename.
- `docs/` stays searchable.

Minimal stub if you want to fast-path:

```bash
for n in 001-slog-handler-wrapper 002-path-dsl 003-httpsnoop-dependency \
         004-dedicated-gin-subpackage 005-context-attrs-inline \
         006-head-truncation-only 007-regex-off-by-default \
         008-single-censor-token; do
  cat > "docs/ADR-${n}.md" <<EOF
# ADR-${n}

**Status**: Accepted

See docs/architecture.md §14 for the full rationale until this file is expanded.
EOF
done
```

You can flesh them out from the architecture doc later; Claude Code will point to the correct numbered file either way.

Finally, create `docs/v2-ideas.md` as the scope-fence overflow buffer:

```bash
cat > docs/v2-ideas.md <<'EOF'
# v2 ideas

Features requested during v1 development that are explicitly deferred.

Format:

```
## <feature name>
Date: YYYY-MM-DD
Proposer: <github handle or "internal">
Why v2: <one sentence>
```
EOF
```

---

## 11. First commit and tag

Now stage and commit everything:

```bash
git add .
git status
```

Review the file list. If anything looks wrong, fix before committing.

```bash
git commit -m "chore: initial project scaffolding

- module layout per architecture doc §2
- Apache 2.0 license
- golangci-lint v2 config
- CI, fuzz, bench workflows
- ADR-001..008 stubs
- CLAUDE.md for agent conventions
"
```

Push to GitHub:

```bash
git push origin main
```

Verify CI runs green at `github.com/JAS0N-SMITH/redactlog/actions`.

### Optional: tag v0.0.1 to verify module proxy

This is worth doing — it catches any module-path typos before you start implementation.

```bash
git tag -s v0.0.1 -m "v0.0.1: scaffolding only"
git push origin v0.0.1
```

Then wait 5 minutes and verify pkg.go.dev sees the module:

```bash
# Should succeed without error:
go list -m github.com/JAS0N-SMITH/redactlog@v0.0.1
```

Or visit [pkg.go.dev/github.com/JAS0N-SMITH/redactlog](https://pkg.go.dev/github.com/JAS0N-SMITH/redactlog) in a browser. If the page doesn't exist, click "Request" on pkg.go.dev to trigger a crawl.

---

## 12. Verification checklist

Before inviting Claude Code, confirm:

- [ ] `go build ./...` succeeds with no errors
- [ ] `go vet ./...` is clean
- [ ] `golangci-lint run` is clean
- [ ] `govulncheck ./...` is clean
- [ ] `go mod tidy` produces no diff
- [ ] CI on GitHub is green for the initial commit
- [ ] `docs/` contains `architecture.md`, `roadmap.md`, `ADR-001.md` through `ADR-008.md`, `v2-ideas.md`
- [ ] `CLAUDE.md` is at the repo root
- [ ] `LICENSE` contains the Apache 2.0 text
- [ ] `SECURITY.md` has your actual email (not `<TODO>`)
- [ ] `go.mod` declares `go 1.23` and lists `httpsnoop`, `gin`, `semconv/v1.26.0` as direct deps
- [ ] The `bench/` directory has its own `go.mod`
- [ ] `.gitignore`, `.editorconfig`, `.golangci.yml` are present
- [ ] GitHub Dependabot is enabled (the `.github/dependabot.yml` file triggers it)

If every box is ticked, you're ready.

---

## 13. Invoke Claude Code

From the repo root:

```bash
claude
```

First prompt should be:

> Read CLAUDE.md, docs/architecture.md, and docs/roadmap.md. Then tell me which milestone we're starting with and what the first concrete task is. Do not write any code yet.

This forces Claude Code to:

1. Load the authoritative references into its context
2. State the milestone explicitly (per CLAUDE.md §15)
3. Propose the first task without premature implementation

Once you're aligned on the first task (typically: implementing the DSL lexer for M2), proceed milestone by milestone per `docs/roadmap.md`.

---

## Appendix: Useful CLI commands during development

Quick reference for the loop you'll run repeatedly:

```bash
# Fast local loop
go test -short ./...

# Full local loop (pre-push)
go test -race ./...
golangci-lint run
govulncheck ./...

# Format everything
golangci-lint fmt

# Coverage
go test -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out           # open in browser
go tool cover -func=coverage.out | tail -1  # summary line

# Benchmarks (local, for benchstat before/after)
go test -run=^$ -bench=. -benchmem -count=10 ./redact > bench-before.txt
# ... make changes ...
go test -run=^$ -bench=. -benchmem -count=10 ./redact > bench-after.txt
go install golang.org/x/perf/cmd/benchstat@latest
benchstat bench-before.txt bench-after.txt

# Fuzz a single target locally
go test -run=^$ -fuzz=FuzzRedactWalk -fuzztime=30s ./redact

# Update a single dependency
go get github.com/felixge/httpsnoop@latest && go mod tidy

# Tidy and check for drift
go mod tidy && git diff go.mod go.sum

# Preview pkg.go.dev rendering locally
pkgsite -http :6060
# then open http://localhost:6060/github.com/JAS0N-SMITH/redactlog

# Tag a release (pre-v1)
git tag -s v0.1.0 -m "v0.1.0: redact engine complete (M2)"
git push origin v0.1.0
```

## Appendix: references

- [golangci-lint v2 install](https://golangci-lint.run/docs/welcome/install/local/)
- [golangci-lint v2 release notes](https://ldez.github.io/blog/2025/03/23/golangci-lint-v2/)
- [govulncheck install & tutorial](https://go.dev/doc/tutorial/govulncheck)
- [govulncheck command reference](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
- [actions/setup-go](https://github.com/actions/setup-go) — v5 and v6 both current; pin your choice
- [Building and testing Go on GitHub Actions](https://docs.github.com/actions/automating-builds-and-tests/building-and-testing-go)
- [Go vulnerability management overview](https://go.dev/security/vuln/)
- [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
- [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
- [Go module reference](https://go.dev/ref/mod)
- [felixge/httpsnoop](https://pkg.go.dev/github.com/felixge/httpsnoop)
- [OpenTelemetry semconv v1.26.0](https://pkg.go.dev/go.opentelemetry.io/otel/semconv/v1.26.0)
- [gin-gonic/gin](https://pkg.go.dev/github.com/gin-gonic/gin)

---

*End of scaffolding guide. Once the verification checklist is complete, hand off to Claude Code per §13.*
