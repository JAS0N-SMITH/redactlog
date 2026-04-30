#!/bin/bash
set -euo pipefail

DATE=$(date +%Y-%m-%d_%H%M%S)
mkdir -p bench/benchmarks
go test -run=^$ -bench=. -benchmem -count=10 ./redact > bench/benchmarks/$DATE.txt

if command -v benchstat >/dev/null 2>&1; then
  if [ -f bench/benchmarks/latest.txt ]; then
    benchstat bench/benchmarks/latest.txt bench/benchmarks/$DATE.txt
  fi
else
  echo "warning: benchstat not found; skipping benchstat comparison"
  echo "To install: run -> go install golang.org/x/perf/cmd/benchstat@latest"
  echo "Make sure \\$GOPATH/bin or \\$GOBIN is in your PATH after install."
fi

ln -sf $DATE.txt bench/benchmarks/latest.txt
