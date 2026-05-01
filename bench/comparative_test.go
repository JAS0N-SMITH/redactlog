package bench_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	redactlog "github.com/JAS0N-SMITH/redactlog"
	redactgin "github.com/JAS0N-SMITH/redactlog/gin"
	"github.com/samber/slog-gin"
	"github.com/samber/slog-http"

	"github.com/JAS0N-SMITH/redactlog/bench"
)

// ── Scenario 1: no-redaction, tiny JSON echo ──────────────────────────────

// BenchmarkNoRedaction_sloghttp — samber/slog-http baseline (net/http tier).
func BenchmarkNoRedaction_sloghttp(b *testing.B) {
	logger := bench.DiscardLogger()
	mw := sloghttp.New(logger)
	srv := httptest.NewServer(mw(bench.NoopHandler()))
	defer srv.Close()
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		bench.DoRequest(b, srv, http.MethodGet, "/", "")
	}
}

// BenchmarkNoRedaction_redactlog — redactlog no-match path (net/http tier).
func BenchmarkNoRedaction_redactlog(b *testing.B) {
	h, err := redactlog.New(
		redactlog.WithLogger(bench.DiscardLogger()),
		redactlog.WithClock(bench.FixedClock()),
	)
	if err != nil {
		b.Fatal(err)
	}
	srv := httptest.NewServer(h.Middleware()(bench.NoopHandler()))
	defer srv.Close()
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		bench.DoRequest(b, srv, http.MethodGet, "/", "")
	}
}

// ── Scenario 1 (Gin tier) ─────────────────────────────────────────────────

// BenchmarkNoRedaction_slogging_gin — samber/slog-gin baseline (Gin tier).
func BenchmarkNoRedaction_slogging_gin(b *testing.B) {
	gin.SetMode(gin.TestMode)
	logger := bench.DiscardLogger()
	r := gin.New()
	r.Use(sloggin.New(logger))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
	srv := httptest.NewServer(r)
	defer srv.Close()
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		bench.DoRequest(b, srv, http.MethodGet, "/", "")
	}
}

// BenchmarkNoRedaction_redactlog_gin — redactlog no-match path (Gin tier).
func BenchmarkNoRedaction_redactlog_gin(b *testing.B) {
	gin.SetMode(gin.TestMode)
	h, err := redactlog.New(
		redactlog.WithLogger(bench.DiscardLogger()),
		redactlog.WithClock(bench.FixedClock()),
	)
	if err != nil {
		b.Fatal(err)
	}
	r := gin.New()
	r.Use(redactgin.New(h))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
	srv := httptest.NewServer(r)
	defer srv.Close()
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		bench.DoRequest(b, srv, http.MethodGet, "/", "")
	}
}

// ── Scenario 2: with-redaction, 10 KB body ───────────────────────────────

// BenchmarkWithRedaction_redactlog — 5 paths + PANDetector (PCI preset parity).
func BenchmarkWithRedaction_redactlog(b *testing.B) {
	h, err := redactlog.NewPCI(
		redactlog.WithLogger(bench.DiscardLogger()),
		redactlog.WithClock(bench.FixedClock()),
		redactlog.WithRequestBody(true),
		redactlog.WithMaxBodyBytes(16384),
		redactlog.WithContentTypes("application/json"),
	)
	if err != nil {
		b.Fatal(err)
	}
	srv := httptest.NewServer(h.Middleware()(bench.EchoHandler()))
	defer srv.Close()
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		bench.DoRequest(b, srv, http.MethodPost, "/", bench.TenKBBodyWithSecrets())
	}
}

// BenchmarkWithRedaction_sloghttp — samber/slog-http with body capture.
// Apples-to-apples: same body size, same body-capture flag;
// samber has no redaction engine so the comparison is structural overhead only.
func BenchmarkWithRedaction_sloghttp(b *testing.B) {
	logger := bench.DiscardLogger()
	mw := sloghttp.New(logger)
	srv := httptest.NewServer(mw(bench.EchoHandler()))
	defer srv.Close()
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		bench.DoRequest(b, srv, http.MethodPost, "/", bench.TenKBBodyWithSecrets())
	}
}

// BenchmarkBodyCapture_64KB — redactlog with 64 KB body (architecture.md target:
// PAN detector on 64 KiB JSON < 250 µs amortized).
func BenchmarkBodyCapture_64KB(b *testing.B) {
	h, err := redactlog.NewPCI(
		redactlog.WithLogger(bench.DiscardLogger()),
		redactlog.WithClock(bench.FixedClock()),
		redactlog.WithRequestBody(true),
		redactlog.WithMaxBodyBytes(65536),
		redactlog.WithContentTypes("application/json"),
	)
	if err != nil {
		b.Fatal(err)
	}
	body64KB := bench.BuildBody64KB()
	srv := httptest.NewServer(h.Middleware()(bench.EchoHandler()))
	defer srv.Close()
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		bench.DoRequest(b, srv, http.MethodPost, "/", body64KB)
	}
}

// ── Scenario 3: SSE streaming overhead per-flush ─────────────────────────

// BenchmarkSSE_redactlog — middleware overhead per SSE flush event.
func BenchmarkSSE_redactlog(b *testing.B) {
	h, err := redactlog.New(
		redactlog.WithLogger(bench.DiscardLogger()),
		redactlog.WithClock(bench.FixedClock()),
	)
	if err != nil {
		b.Fatal(err)
	}
	srv := httptest.NewServer(h.Middleware()(bench.SSEHandler()))
	defer srv.Close()
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		bench.DoRequest(b, srv, http.MethodGet, "/sse", "")
	}
}

// BenchmarkSSE_sloghttp — samber/slog-http SSE overhead per-flush event.
func BenchmarkSSE_sloghttp(b *testing.B) {
	logger := bench.DiscardLogger()
	mw := sloghttp.New(logger)
	srv := httptest.NewServer(mw(bench.SSEHandler()))
	defer srv.Close()
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		bench.DoRequest(b, srv, http.MethodGet, "/sse", "")
	}
}
