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
	// Read maxBodyBytes+1 so we can detect truncation: if we read more than
	// maxBodyBytes we know the body is larger without consuming the whole stream.
	limited := io.LimitedReader{R: r, N: int64(maxBodyBytes) + 1}
	n, _ := io.Copy(buf, &limited)
	captured := buf.Bytes()
	truncated := n > int64(maxBodyBytes)

	// Cap the logged bytes at maxBodyBytes; the extra byte was only for detection.
	logBytes := captured
	if truncated && len(logBytes) > maxBodyBytes {
		logBytes = logBytes[:maxBodyBytes]
	}

	// Restore the full captured slice (including the detection byte) so the
	// handler sees all bytes the middleware read, followed by the remaining body.
	restoredBody := io.NopCloser(io.MultiReader(bytes.NewReader(captured), r))

	return logBytes, truncated, restoredBody
}
