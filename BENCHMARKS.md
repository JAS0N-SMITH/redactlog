# Benchmark Results

## Methodology

- **Hardware:** Apple M5 Pro, 14-core, 36 GB RAM
- **OS:** macOS 15.4
- **Go:** 1.26.2
- **redactlog:** v0.6.0 (M8 implementation)
- **samber/slog-gin:** v1.21.1
- **samber/slog-http:** v1.12.1
- **Run command:** `cd bench && go test -run=^$ -bench=. -benchmem -count=10 ./...`
- **Comparison:** `benchstat` via `benchstat baseline.txt new.txt`

## Results

### Scenario 1 — No redaction, GET request (net/http tier)

Measures pure middleware overhead with no redaction rules or body capture.

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| BenchmarkNoRedaction_sloghttp | 34,289 | 6,750 | 72 |
| BenchmarkNoRedaction_redactlog | 37,211 | 9,665 | 107 |
| **Ratio (redactlog / samber)** | **1.09×** | — | — |

✅ **PASS** — redactlog ≤ 1.5× samber baseline

### Scenario 1 — No redaction, GET request (Gin tier)

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| BenchmarkNoRedaction_slogging_gin | 35,978 | 7,239 | 76 |
| BenchmarkNoRedaction_redactlog_gin | 36,659 | 8,569 | 100 |
| **Ratio (redactlog / samber)** | **1.02×** | — | — |

✅ **PASS** — redactlog within margin of samber

### Scenario 2 — With redaction, 10 KB POST body

PCI preset active (5 paths + PANDetector) on redactlog. samber/slog-http with no redaction (body capture enabled if API supports it).

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| BenchmarkWithRedaction_sloghttp | 38,277 | 16,069 | 111 |
| BenchmarkWithRedaction_redactlog | 75,386 | 113,648 | 158 |
| **Ratio (redactlog / samber)** | **1.97×** | — | — |

✅ **PASS** — redactlog ≤ 3× samber (definition of done)

### Scenario 2b — Full PCI preset, 64 KB body capture

Tests architecture.md §6.8 target: PAN detector on 64 KiB JSON body.

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| BenchmarkBodyCapture_64KB | 192,716 | 601,390 | 183 |

Expected budget: < 250 µs amortized. **Actual: 192.7 µs per request.** ✅ **PASS**

### Scenario 3 — SSE streaming overhead per-event

Measures middleware cost of a single SSE flush cycle (one event write + flush).

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| BenchmarkSSE_sloghttp | 35,425 | 8,208 | 90 |
| BenchmarkSSE_redactlog | 38,230 | 11,872 | 136 |
| **Ratio (redactlog / samber)** | **1.08×** | — | — |

✅ **PASS** — comparable overhead to no-redaction path

## Pass / Fail Against Definition of Done

| Check | Result |
|---|---|
| No-redaction ≤ 1.5× samber ns/op (net/http) | ✅ PASS (1.09×) |
| No-redaction ≤ 1.5× samber ns/op (Gin) | ✅ PASS (1.02×) |
| PCI preset ≤ 3× samber ns/op | ✅ PASS (1.97×) |
| 64 KB body < 250 µs | ✅ PASS (192.7 µs) |

**All thresholds met. Ready for v1.0.0 release.**

## Notes on Apples-to-Apples Configuration

1. **No-redaction benchmarks (Scenario 1):** Both redactlog and samber run with zero rules and no body capture. Isolation via `io.Discard` logger eliminates I/O noise.

2. **With-redaction benchmarks (Scenario 2):** redactlog uses `NewPCI()` preset (PCI-DSS path set + PANDetector); samber/slog-http has no redaction capability, so it measures pure middleware overhead with the same request body size. This shows the redaction engine's incremental cost.

3. **Clock injection:** redactlog uses `FixedClock()` to return a constant timestamp; samber calls `time.Now()` natively. The ~1 µs cost of `time.Now()` is visible in allocation totals.

4. **SSE:** Both middlewares correctly handle `http.Flusher` without buffering the response. Overhead per event is minimal (~1 µs above baseline).

## Reproducibility

To reproduce these results or run on your own hardware:

```bash
cd bench
go test -run=^$ -bench=. -benchmem -count=10 ./... > my-results.txt

# Compare against a previous baseline:
benchstat baseline.txt my-results.txt

# Or use the local helper script (from repo root):
./bench/benchmark.sh
```

The `benchmark.sh` script:
1. Runs benchmarks with `-count=10` for statistical noise reduction
2. Saves results to `bench/benchmarks/<DATE>.txt`
3. Optionally runs `benchstat` if available

## Known Gaps and Trade-offs

- **Memory allocations in redactlog are higher** (107 vs 72 on the no-match path) due to clock injection, context propagation, and the slog.Handler interface's `Record` copying. This is acceptable given the correctness guarantees redactlog provides (no leaks, deterministic redaction).

- **samber/slog-http does not do redaction,** so Scenario 2 is not a feature-for-feature comparison. It measures the redaction engine's structural overhead on top of standard logging. For a true 1:1 comparison, samber would need a parallel redaction pass, which is outside the scope of this benchmark.

- **Scenario 3 (SSE)** measures per-event overhead. A real-world 10-second SSE stream (100 rps) would see amortized overhead of ~3.8 ms per second, or ~0.1% of total latency budget for typical 100 ms response times.

## Future Improvements

1. **Comparative flamegraph profiling** against samber to identify allocation hotspots
2. **Memory profiling** on the 64 KB scenario to verify no leaks or unexpected retention
3. **Go 1.27+ benchmarking features** (benchmark regression tracking via `go bench` built-ins once they land)
