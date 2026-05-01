package bench

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// DiscardLogger returns a *slog.Logger that discards all output.
// Used to isolate middleware overhead from I/O overhead in benchmarks.
func DiscardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// FixedClock returns a func() time.Time that always returns the same instant,
// satisfying the project's clock-injection requirement and eliminating
// time.Now() noise from benchmark measurements.
func FixedClock() func() time.Time {
	t := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

// TenKBBodyWithSecrets returns a ~10 KB JSON payload for Scenario 2.
// Contains 3 fields that the PCI preset will redact: card.pan, user.email, auth.token.
func TenKBBodyWithSecrets() string {
	return tenKBBodyWithSecrets
}

var tenKBBodyWithSecrets = buildTenKBBody()

func buildTenKBBody() string {
	// Build a ~10 KB JSON payload with 3 sensitive fields in a realistic structure.
	var sb strings.Builder
	sb.WriteString(`{"card":{"pan":"4111111111111111"},"user":{"email":"alice@example.test","name":"Alice"},"auth":{"token":"Bearer eyJhbGc"},"items":[`)
	pad := strings.Repeat(`{"id":1,"sku":"WIDGET","qty":5,"price":9.99},`, 200) // ~8 KB padding
	sb.WriteString(pad[:len(pad)-1])
	sb.WriteString(`]}`)
	return sb.String()
}

// BuildBody64KB constructs a ~64 KB JSON payload with sensitive fields.
func BuildBody64KB() string {
	var sb strings.Builder
	sb.WriteString(`{"card":{"pan":"4111111111111111"},"items":[`)
	entry := `{"id":1,"sku":"WIDGET-A","qty":10,"price":99.99,"meta":"` + strings.Repeat("x", 100) + `"},`
	for sb.Len() < 63*1024 {
		sb.WriteString(entry)
	}
	// trim trailing comma and close
	s := sb.String()
	return s[:len(s)-1] + "]}"
}

// EchoHandler returns 200 OK with the request body echoed back.
func EchoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.Copy(w, r.Body)
	})
}

// NoopHandler returns 200 OK immediately with no body.
func NoopHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// SSEHandler writes a single SSE event and flushes. Used for Scenario 3.
func SSEHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "data: {\"event\":\"ping\"}\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	})
}

// DoRequest fires a GET or POST against the given server and discards the response.
// It does NOT reuse connections deliberately — each call exercises the full handler chain.
func DoRequest(b *testing.B, srv *httptest.Server, method, path, body string) {
	b.Helper()
	var req *http.Request
	var err error
	if body != "" {
		req, err = http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = http.NewRequest(method, srv.URL+path, nil)
	}
	if err != nil {
		b.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		b.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}
