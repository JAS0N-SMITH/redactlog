package gin_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	ggin "github.com/gin-gonic/gin"

	"github.com/JAS0N-SMITH/redactlog"
	redactgin "github.com/JAS0N-SMITH/redactlog/gin"
)

func init() {
	ggin.SetMode(ggin.TestMode)
}

// newTestHandler builds a redactlog.Handler that logs into buf as JSON.
func newTestHandler(t *testing.T, buf *bytes.Buffer) *redactlog.Handler {
	t.Helper()
	logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h, err := redactlog.New(redactlog.WithLogger(logger))
	if err != nil {
		t.Fatalf("redactlog.New: %v", err)
	}
	return h
}

// newEngine builds a gin.Engine with the middleware pre-registered.
func newEngine(h *redactlog.Handler) *ggin.Engine {
	r := ggin.New()
	r.Use(redactgin.New(h))
	return r
}

// TestGinMiddleware_TableDriven covers the primary HTTP flows.
func TestGinMiddleware_TableDriven(t *testing.T) {
	tests := []struct {
		name           string
		setup          func(r *ggin.Engine)
		method         string
		path           string
		body           string
		contentType    string
		wantStatus     int
		wantLogContain []string
	}{
		{
			name: "GET 200 logs method and status",
			setup: func(r *ggin.Engine) {
				r.GET("/ping", func(c *ggin.Context) {
					c.String(http.StatusOK, "pong")
				})
			},
			method:     "GET",
			path:       "/ping",
			wantStatus: http.StatusOK,
			// status_code is emitted as a JSON integer, not a quoted string.
			wantLogContain: []string{`"GET"`, `"http.response.status_code":200`},
		},
		{
			name: "POST 201 with JSON body",
			setup: func(r *ggin.Engine) {
				r.POST("/items", func(c *ggin.Context) {
					c.JSON(http.StatusCreated, ggin.H{"id": 1})
				})
			},
			method:         "POST",
			path:           "/items",
			body:           `{"name":"widget"}`,
			contentType:    "application/json",
			wantStatus:     http.StatusCreated,
			wantLogContain: []string{`"POST"`, `"http.response.status_code":201`},
		},
		{
			name: "404 unregistered path logs warn level",
			setup: func(r *ggin.Engine) {
				// No route registered; gin returns 404.
			},
			method:         "GET",
			path:           "/does-not-exist",
			wantStatus:     http.StatusNotFound,
			wantLogContain: []string{`"http.response.status_code":404`, `"WARN"`},
		},
		{
			name: "route template injected as http.route",
			setup: func(r *ggin.Engine) {
				r.GET("/users/:id", func(c *ggin.Context) {
					c.String(http.StatusOK, c.Param("id"))
				})
			},
			method:         "GET",
			path:           "/users/42",
			wantStatus:     http.StatusOK,
			wantLogContain: []string{`"http.route":"/users/:id"`},
		},
		{
			name: "5xx promotes to ERROR level",
			setup: func(r *ggin.Engine) {
				r.GET("/fail", func(c *ggin.Context) {
					c.Status(http.StatusInternalServerError)
				})
			},
			method:         "GET",
			path:           "/fail",
			wantStatus:     http.StatusInternalServerError,
			wantLogContain: []string{`"http.response.status_code":500`, `"ERROR"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			h := newTestHandler(t, &buf)
			r := newEngine(h)
			tt.setup(r)

			var reqBody io.Reader
			if tt.body != "" {
				reqBody = strings.NewReader(tt.body)
			}
			req := httptest.NewRequestWithContext(context.Background(), tt.method, tt.path, reqBody)
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status: got %d, want %d", w.Code, tt.wantStatus)
			}
			logged := buf.String()
			for _, want := range tt.wantLogContain {
				if !strings.Contains(logged, want) {
					t.Errorf("log missing %q\nlog: %s", want, logged)
				}
			}
		})
	}
}

// TestGinMiddleware_SSEFlusherPreserved verifies that Flush is passed through
// the httpsnoop + gin double-wrap without breaking SSE streams.
func TestGinMiddleware_SSEFlusherPreserved(t *testing.T) {
	var buf bytes.Buffer
	h := newTestHandler(t, &buf)
	r := newEngine(h)

	r.GET("/events", func(c *ggin.Context) {
		c.Header("Content-Type", "text/event-stream")
		c.Header("Cache-Control", "no-cache")
		c.Status(http.StatusOK)
		for i := range 3 {
			fmt.Fprintf(c.Writer, "data: event%d\n\n", i)
			c.Writer.Flush()
		}
	})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/events", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", w.Code)
	}
	body := w.Body.String()
	for i := range 3 {
		want := fmt.Sprintf("data: event%d", i)
		if !strings.Contains(body, want) {
			t.Errorf("SSE body missing %q\nbody: %s", want, body)
		}
	}
}

// TestGinMiddleware_HijackPreserved verifies that the Hijacker interface
// survives the httpsnoop + gin double-wrap, enabling raw TCP upgrades.
func TestGinMiddleware_HijackPreserved(t *testing.T) {
	var buf bytes.Buffer
	h := newTestHandler(t, &buf)
	r := newEngine(h)

	var hijackOK atomic.Bool
	r.GET("/ws", func(c *ggin.Context) {
		// Attempt to hijack the connection (simulates WebSocket upgrade).
		hj, ok := c.Writer.(http.Hijacker)
		if !ok {
			c.Status(http.StatusInternalServerError)
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			c.Status(http.StatusInternalServerError)
			return
		}
		hijackOK.Store(true)
		_ = rw
		_ = conn.Close()
	})

	// httptest.NewRecorder does NOT implement Hijacker, so we need a real
	// net.Conn pair to test hijacking end-to-end.
	server := httptest.NewServer(r)
	defer server.Close()

	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_, err = fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: localhost\r\n\r\n")
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read until the server closes; we just need it to not panic.
	_, _ = io.ReadAll(bufio.NewReader(conn))

	if !hijackOK.Load() {
		t.Error("http.Hijacker not available through gin + httpsnoop double-wrap")
	}
}

// TestGinMiddleware_PanicRecovery verifies that panic recovery middleware
// registered AFTER redactgin.New sees the panic as a 500, and the logger
// emits an ERROR-level record.
func TestGinMiddleware_PanicRecovery(t *testing.T) {
	var buf bytes.Buffer
	h := newTestHandler(t, &buf)

	r := ggin.New()
	r.Use(redactgin.New(h))
	r.Use(ggin.Recovery()) // Recovery after logger: logger sees 500.
	r.GET("/boom", func(c *ggin.Context) {
		panic("deliberate test panic")
	})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/boom", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status: got %d, want 500", w.Code)
	}
	logged := buf.String()
	if !strings.Contains(logged, `"http.response.status_code":500`) {
		t.Errorf("expected status_code 500 in log\nlog: %s", logged)
	}
	if !strings.Contains(logged, `"ERROR"`) {
		t.Errorf("expected ERROR level in log\nlog: %s", logged)
	}
}

// TestNewWithConfig verifies the convenience constructor.
func TestNewWithConfig(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	fn, err := redactgin.NewWithConfig(redactlog.Config{Logger: logger})
	if err != nil {
		t.Fatalf("NewWithConfig: %v", err)
	}

	r := ggin.New()
	r.Use(fn)
	r.GET("/ok", func(c *ggin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/ok", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", w.Code)
	}
	if buf.Len() == 0 {
		t.Error("expected log output, got none")
	}
}
