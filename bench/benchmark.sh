#!/bin/bash
set -euo pipefail

# Ensure we're in the bench/ directory
cd "$(dirname "$0")"

DATE=$(date +%Y-%m-%d_%H%M%S)
mkdir -p benchmarks
go test -run=^$ -bench=. -benchmem -count=10 ./... > benchmarks/$DATE.txt

if command -v benchstat >/dev/null 2>&1; then
  if [ -f benchmarks/latest.txt ]; then
    benchstat benchmarks/latest.txt benchmarks/$DATE.txt
  fi
else
  echo "warning: benchstat not found; skipping benchstat comparison"
  echo "To install: run -> go install golang.org/x/perf/cmd/benchstat@latest"
  echo "Make sure \$GOPATH/bin or \$GOBIN is in your PATH after install."
fi

ln -sf $DATE.txt benchmarks/latest.txt
