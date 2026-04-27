package httpmw

import (
	"bytes"
	"io"
)

// captureRequestBody reads and buffers the request body up to maxBodyBytes,
// preserving the original body for the handler via io.NopCloser wrapping.
// Returns the captured bytes and whether truncation occurred.
func captureRequestBody(r io.Reader, maxBodyBytes int) ([]byte, bool, io.ReadCloser) {
	buf := new(bytes.Buffer)
	// Use LimitedReader to detect truncation: if we read maxBodyBytes+1,
	// we know the body is larger.
	limited := io.LimitedReader{R: r, N: int64(maxBodyBytes) + 1}
	n, _ := io.Copy(buf, &limited)
	captured := buf.Bytes()
	truncated := n > int64(maxBodyBytes)

	// Restore the body by wrapping the captured data for re-reading.
	// If the body was truncated, we only restore what we captured.
	restoredBody := io.NopCloser(io.MultiReader(bytes.NewReader(captured), r))

	return captured, truncated, restoredBody
}
