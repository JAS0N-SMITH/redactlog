package httpmw

import (
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/JAS0N-SMITH/redactlog/redact"
)

// randReader is the random source for UUIDv4 generation.
var randReader = rand.Reader

// Config holds HTTP middleware configuration.
type Config struct {
	// Logger is the slog.Logger used to emit request/response records.
	Logger *slog.Logger

	// Redactor applies path-based redaction to captured data.
	Redactor *redact.Engine

	// CaptureRequestBody enables buffering the inbound request body.
	CaptureRequestBody bool

	// CaptureResponseBody enables buffering the outbound response body.
	CaptureResponseBody bool

	// MaxBodyBytes limits captured body size. Must be in [1024, 1048576].
	MaxBodyBytes int

	// ContentTypes restricts body capture to specific MIME types.
	ContentTypes []string

	// HeaderDenylist specifies headers to omit from logs (unless overridden by allowlist).
	HeaderDenylist []string

	// HeaderAllowlist, if non-empty, inverts the filter: only these headers are logged.
	HeaderAllowlist []string

	// SensitiveQueryParams specifies query parameter names to redact.
	SensitiveQueryParams []string

	// RequestIDHeader is the header name to check for / propagate a request ID.
	RequestIDHeader string

	// GenerateRequestID controls whether to synthesize a UUIDv4 if no ID is present.
	GenerateRequestID bool

	// SkipPaths lists request paths to skip logging (exact match).
	SkipPaths []string

	// Clock injects a time source for deterministic testing.
	Clock func() time.Time

	// RouteFunc, if non-nil, is called after the handler returns to obtain the
	// matched route template (e.g. "/users/:id"). The return value is emitted as
	// http.route. Framework adapters (e.g. the gin adapter) use this to surface
	// the route template, which is only known after the handler chain runs.
	RouteFunc func(*http.Request) string

	// StatusFunc, if non-nil and the status captured via httpsnoop is 0, is
	// called to obtain the response status code. Needed for frameworks (e.g.
	// gin) whose ResponseWriter tracks status internally and may not call the
	// underlying http.ResponseWriter.WriteHeader through httpsnoop's wrapper.
	StatusFunc func() int
}

// Middleware returns an http.Handler middleware that captures request/response metadata
// and bodies, applying the redactor before emission.
func Middleware(cfg Config) func(http.Handler) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check skip list.
			if slices.Contains(cfg.SkipPaths, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			ctx := r.Context()

			// Extract or generate request ID.
			reqID := r.Header.Get(cfg.RequestIDHeader)
			if reqID == "" && cfg.GenerateRequestID {
				reqID = generateUUIDv4()
			}
			if reqID != "" {
				w.Header().Set(cfg.RequestIDHeader, reqID)
				ctx = context.WithValue(ctx, ctxRequestIDKey{}, reqID)
			}

			// Capture request body if enabled.
			var reqBody []byte
			var reqBodyTruncated bool
			if cfg.CaptureRequestBody && contentTypeAllowed(r.Header.Get("Content-Type"), cfg.ContentTypes) {
				captured, truncated, restoredBody := captureRequestBody(r.Body, cfg.MaxBodyBytes)
				reqBody = captured
				reqBodyTruncated = truncated
				r.Body = restoredBody
			}

			// Scrub query parameters.
			scrubbedURL := r.URL
			if len(cfg.SensitiveQueryParams) > 0 {
				scrubbedURL = scrubQueryParams(r.URL, cfg.SensitiveQueryParams)
			}

			// Wrap response writer.
			respStart := cfg.Clock()
			capturedResp := &capturedResponse{}
			wrappedWriter := wrapResponseWriter(w, capturedResp, cfg.MaxBodyBytes, cfg.CaptureResponseBody)

			// Call the handler.
			r = r.WithContext(ctx)
			next.ServeHTTP(wrappedWriter, r)

			respEnd := cfg.Clock()

			// Build log attributes.
			capturedResp.Duration = respEnd.Sub(respStart)
			logRequest(ctx, cfg, r, scrubbedURL, reqID, reqBody, reqBodyTruncated, capturedResp)
		})
	}
}

// logRequest emits a log record for the request/response pair.
func logRequest(ctx context.Context, cfg Config, r *http.Request, scrubbedURL *url.URL, reqID string, reqBody []byte, reqBodyTruncated bool, resp *capturedResponse) {
	// Build attributes for the log record.
	attrs := []slog.Attr{
		slog.String("http.request.method", r.Method),
		slog.String("url.path", scrubbedURL.Path),
		slog.String("server.address", r.Host),
		slog.String("client.address", clientAddr(r)),
		slog.String("network.protocol.version", r.Proto),
		slog.String("user_agent.original", r.Header.Get("User-Agent")),
	}

	// Add route template if a RouteFunc provided one (set by framework adapters post-handler).
	if cfg.RouteFunc != nil {
		if route := cfg.RouteFunc(r); route != "" {
			attrs = append(attrs, slog.String("http.route", route))
		}
	}

	// Add request ID if present.
	if reqID != "" {
		attrs = append(attrs, slog.String("http.request.id", reqID))
	}

	// Add query if present.
	if scrubbedURL.RawQuery != "" {
		attrs = append(attrs, slog.String("url.query", scrubbedURL.RawQuery))
	}

	// Add request headers (scrubbed).
	if len(r.Header) > 0 {
		hdr := scrubHeaders(r.Header, cfg.HeaderDenylist, cfg.HeaderAllowlist)
		for k, vv := range hdr {
			for _, v := range vv {
				attrs = append(attrs, slog.String("http.request.header."+strings.ToLower(k), v))
			}
		}
	}

	// Add request body if captured.
	if len(reqBody) > 0 {
		attrs = append(attrs, slog.String("http.request.body", string(reqBody)))
		attrs = append(attrs, slog.Bool("http.request.body.truncated", reqBodyTruncated))
	}

	// Resolve the response status. httpsnoop captures it for plain net/http;
	// framework adapters (gin) supply StatusFunc because their ResponseWriter
	// tracks status internally, bypassing the WriteHeader hook.
	status := resp.Status
	if status == 0 && cfg.StatusFunc != nil {
		status = cfg.StatusFunc()
	}
	if status == 0 {
		status = http.StatusOK
	}

	// Add response status.
	attrs = append(attrs, slog.Int("http.response.status_code", status))

	// Add response headers (scrubbed).
	if len(resp.Header) > 0 {
		hdr := scrubHeaders(resp.Header, cfg.HeaderDenylist, cfg.HeaderAllowlist)
		for k, vv := range hdr {
			for _, v := range vv {
				attrs = append(attrs, slog.String("http.response.header."+strings.ToLower(k), v))
			}
		}
	}

	// Add response body if captured.
	if len(resp.Body) > 0 {
		attrs = append(attrs, slog.String("http.response.body", string(resp.Body)))
		attrs = append(attrs, slog.Bool("http.response.body.truncated", resp.BodyTruncated))
	}

	// Add duration.
	attrs = append(attrs, slog.Duration("http.duration", resp.Duration))

	// Emit the log record.
	level := slog.LevelInfo
	if status >= 500 {
		level = slog.LevelError
	} else if status >= 400 && status < 500 {
		level = slog.LevelWarn
	}

	cfg.Logger.LogAttrs(ctx, level, "http_request", attrs...)
}

// scrubQueryParams returns a URL with sensitive query parameters replaced with ***.
func scrubQueryParams(u *url.URL, sensitiveParams []string) *url.URL {
	if u.RawQuery == "" {
		return u
	}

	q := u.Query()
	for _, param := range sensitiveParams {
		if _, ok := q[param]; ok {
			q[param] = []string{"***"}
		}
	}

	scrubbed := *u
	scrubbed.RawQuery = q.Encode()
	return &scrubbed
}

// contentTypeAllowed checks if the given content type is in the allowed list.
func contentTypeAllowed(ct string, allowed []string) bool {
	if ct == "" {
		return false
	}

	// Extract media type (before semicolon).
	parts := strings.Split(ct, ";")
	mediaType := strings.TrimSpace(parts[0])

	for _, a := range allowed {
		if strings.EqualFold(mediaType, a) {
			return true
		}
	}
	return false
}

// clientAddr extracts the client IP address from the request.
func clientAddr(r *http.Request) string {
	// Check X-Forwarded-For first (common in proxied environments).
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs; take the first.
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// Fall back to RemoteAddr, stripping port.
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// generateUUIDv4 generates a random UUIDv4 string.
func generateUUIDv4() string {
	// Inline UUIDv4 generation to avoid external dependency.
	// This is a simple random-based implementation sufficient for request IDs.
	b := make([]byte, 16)
	if _, err := io.ReadFull(randReader, b); err != nil {
		// Fallback: shouldn't happen, but provide something.
		return "00000000-0000-0000-0000-000000000000"
	}

	// Set version to 4 and variant to RFC 4122.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	return formatUUID(b)
}

// formatUUID formats a 16-byte array as a UUID string.
func formatUUID(b []byte) string {
	return strings.Join([]string{
		hexEncode(b[0:4]),
		hexEncode(b[4:6]),
		hexEncode(b[6:8]),
		hexEncode(b[8:10]),
		hexEncode(b[10:16]),
	}, "-")
}

// hexEncode encodes bytes as hex.
func hexEncode(b []byte) string {
	const hex = "0123456789abcdef"
	s := make([]byte, len(b)*2)
	for i, v := range b {
		s[i*2] = hex[v>>4]
		s[i*2+1] = hex[v&0x0f]
	}
	return string(s)
}

// Context key type for request ID.
type ctxRequestIDKey struct{}
