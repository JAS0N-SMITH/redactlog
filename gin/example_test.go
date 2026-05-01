package gin_test

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"os"

	"github.com/gin-gonic/gin"

	"github.com/JAS0N-SMITH/redactlog"
	redactgin "github.com/JAS0N-SMITH/redactlog/gin"
)

// Example_gin demonstrates the Gin adapter.
// It shows how to wire redactlog into a Gin router, register the middleware,
// and make a test request to verify that response bodies are redacted.
func Example_gin() {
	// Suppress Gin startup spam in test output.
	gin.SetMode(gin.TestMode)

	// Create a redactlog handler with the PCI preset (includes PAN detection).
	h, _ := redactlog.NewPCI(
		redactlog.WithLogger(slog.New(slog.NewJSONHandler(os.Stdout, nil))),
		redactlog.WithRequestBody(true),
		redactlog.WithResponseBody(true),
	)

	// Set up a Gin router.
	r := gin.New()

	// Register redactlog middleware. It should come before recovery so panics
	// are logged as 500 responses rather than 200.
	r.Use(redactgin.New(h))
	r.Use(gin.Recovery())

	// Add a simple route that returns a response containing a sensitive field.
	r.POST("/pay", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "ok",
			"pan":    "4111111111111111", // Will be redacted by PCI preset
			"cvv":    "123",              // Will be redacted by PCI preset
		})
	})

	// Simulate a request to the route.
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/pay", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	// The middleware logs the request/response. The response body contains
	// pan and cvv fields, which the PCI preset redacts to "***".
	// Output will show the response logged with pan and cvv censored.
}
