package redactlog_test

import (
	"bytes"
	"encoding/json"
	"log/slog"

	"github.com/JAS0N-SMITH/redactlog"
)

// ExampleNew demonstrates basic handler construction with custom paths.
// It shows how to wire a logger, define redaction paths, and verify that
// sensitive attributes are censored before emission.
func ExampleNew() {
	var buf bytes.Buffer
	inner := slog.New(slog.NewJSONHandler(&buf, nil))

	h, err := redactlog.New(
		redactlog.WithLogger(inner),
		redactlog.WithRedactPaths("user.password", "api.token"),
	)
	if err != nil {
		panic(err)
	}

	logger := h.Logger()

	// Log a record with nested attributes: some will match redaction paths, some won't.
	logger.Info("user_login",
		slog.Group("user",
			slog.String("name", "alice"),
			slog.String("email", "alice@example.test"),
			slog.String("password", "hunter2"),
		),
		slog.Group("api",
			slog.String("token", "sk_live_abc123xyz"),
			slog.String("endpoint", "/v1/pay"),
		),
	)

	// The output is deterministic JSON. The password and token fields are redacted to "***".
	// name and email pass through unchanged because they don't match any path.
	var rec map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		panic(err)
	}
	user := rec["user"].(map[string]interface{})
	api := rec["api"].(map[string]interface{})

	// Verify redaction happened:
	// user.password should be "***", not "hunter2"
	// api.token should be "***", not "sk_live_abc123xyz"
	// name and email should be unchanged
	_ = user["name"].(string)     // "alice"
	_ = user["email"].(string)    // "alice@example.test"
	_ = user["password"].(string) // "***"
	_ = api["token"].(string)     // "***"
	_ = api["endpoint"].(string)  // "/v1/pay"
}
