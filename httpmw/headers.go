package httpmw

import (
	"net/http"
	"strings"
)

// scrubHeaders applies denylist or allowlist filtering to HTTP headers.
// If allowlist is non-empty, only those headers are returned (allowlist takes precedence).
// Otherwise, headers matching the denylist are excluded.
// Header names are matched case-insensitively.
func scrubHeaders(h http.Header, denylist, allowlist []string) http.Header {
	result := make(http.Header)

	if len(allowlist) > 0 {
		// Allowlist mode: only include headers in the list.
		for _, name := range allowlist {
			canonical := http.CanonicalHeaderKey(name)
			if vv := h[canonical]; len(vv) > 0 {
				result[canonical] = append([]string(nil), vv...)
			}
		}
	} else {
		// Denylist mode: exclude headers in the list.
		denySet := make(map[string]bool)
		for _, name := range denylist {
			denySet[strings.ToLower(name)] = true
		}

		for k, vv := range h {
			if !denySet[strings.ToLower(k)] {
				result[k] = append([]string(nil), vv...)
			}
		}
	}

	return result
}
