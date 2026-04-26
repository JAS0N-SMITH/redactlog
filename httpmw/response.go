package httpmw

import (
	"net/http"
	"time"

	"github.com/felixge/httpsnoop"
)

// capturedResponse holds captured response metadata and body.
type capturedResponse struct {
	Status        int
	Header        http.Header
	Body          []byte
	BodyTruncated bool
	Streaming     bool
	Duration      time.Duration
}

// isStreamingContentType checks if the content type indicates streaming (SSE, chunked, etc).
func isStreamingContentType(ct string) bool {
	switch ct {
	case "text/event-stream", "text/plain", "application/octet-stream":
		return true
	}
	return false
}

// wrapResponseWriter wraps the response writer to capture status, headers, and optionally body.
// Uses httpsnoop.Wrap to preserve http.Flusher, http.Hijacker, http.Pusher, io.ReaderFrom,
// and http.ResponseController interfaces per ADR-003.
// Detects streaming responses (SSE) and disables body buffering for them.
func wrapResponseWriter(w http.ResponseWriter, captured *capturedResponse, maxBodyBytes int, captureBody bool, contentTypes []string) http.ResponseWriter {
	captured.Header = make(http.Header)

	hooks := httpsnoop.Hooks{
		WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
			return func(code int) {
				captured.Status = code
				// Copy headers before WriteHeader is called.
				for k, vv := range w.Header() {
					captured.Header[k] = append([]string(nil), vv...)
				}

				// Detect streaming content type at WriteHeader time.
				contentType := w.Header().Get("Content-Type")
				if isStreamingContentType(contentType) {
					captured.Streaming = true
				}

				next(code)
			}
		},
	}

	if captureBody {
		hooks.Write = func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
			return func(b []byte) (int, error) {
				// Don't buffer if streaming.
				if captured.Streaming {
					return next(b)
				}

				if len(captured.Body) < maxBodyBytes {
					room := maxBodyBytes - len(captured.Body)
					if len(b) <= room {
						captured.Body = append(captured.Body, b...)
					} else {
						captured.Body = append(captured.Body, b[:room]...)
						captured.BodyTruncated = true
					}
				} else if len(captured.Body) == maxBodyBytes {
					captured.BodyTruncated = true
				}
				return next(b)
			}
		}

		// Detect streaming: if Flush is called, mark as streaming and stop buffering.
		hooks.Flush = func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc {
			return func() {
				captured.Streaming = true
				next()
			}
		}
	}

	return httpsnoop.Wrap(w, hooks)
}
