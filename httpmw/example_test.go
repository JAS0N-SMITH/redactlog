package httpmw_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/JAS0N-SMITH/redactlog/httpmw"
	"github.com/JAS0N-SMITH/redactlog/redact"
)

// Example_httpmw demonstrates the HTTP middleware in isolation.
// It constructs an httpmw.Config directly, wraps an http.Handler with the
// middleware, and makes a test request to show how headers and metadata
// are captured and logged.
func Example_httpmw() {
	// Create a redaction engine with custom paths.
	engine, _ := redact.New([]string{"authorization"}, redact.Options{})

	// Create a logger to receive the middleware's logged records.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// Configure the HTTP middleware.
	cfg := httpmw.Config{
		Redactor:            engine,
		Logger:              logger,
		CaptureRequestBody:  true,
		CaptureResponseBody: true,
	}

	// Create a simple HTTP handler that echoes a 200 response.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Wrap the handler with the middleware.
	mw := httpmw.Middleware(cfg)

	// Simulate an HTTP request with a sensitive header.
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer sk_live_secret123")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	// Call the wrapped handler.
	mw(handler).ServeHTTP(w, req)

	// The middleware logs request metadata (method, path, status, headers).
	// The Authorization header value is redacted before logging.
	// Output will show the request logged with Authorization: *** (or omitted).
}
