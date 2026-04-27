// Package gin adapts redactlog's http.Handler middleware to gin.HandlerFunc.
// This is the only package in the module that imports gin-gonic/gin.
//
// Usage:
//
//	h, _ := redactlog.NewPCI(redactlog.WithLogger(slog.Default()))
//	r := gin.New()
//	r.Use(redactgin.New(h))
//
// Panic recovery ordering: register gin.Recovery() AFTER redactgin.New(h) so
// that the logger sees panics as 500 responses. If recovery is registered
// first, the logger records a 200 because the panic is caught before the
// response is completed.
//
// See docs/ADR-004-dedicated-gin-subpackage.md for the adapter rationale.
package gin

import (
	"net/http"

	ggin "github.com/gin-gonic/gin"

	"github.com/JAS0N-SMITH/redactlog"
)

// New returns a gin.HandlerFunc that wraps h's net/http middleware around
// Gin's handler chain. It captures request/response metadata via httpmw and
// injects Gin's route template (c.FullPath()) as the http.route log attribute.
//
// The returned HandlerFunc is safe for concurrent use and should be registered
// once via r.Use(redactgin.New(h)).
func New(h *redactlog.Handler) ggin.HandlerFunc {
	return func(c *ggin.Context) {
		// Both funcs close over c and are called by httpmw after c.Next() returns.
		//
		// routeFunc: c.FullPath() is resolved only after gin routes the request.
		// statusFunc: gin's ResponseWriter tracks status internally; its WriteHeader
		// may not propagate through httpsnoop's hook, so we read it directly.
		routeFunc := func(_ *http.Request) string { return c.FullPath() }
		statusFunc := func() int { return c.Writer.Status() }
		mw := h.MiddlewareForGin(routeFunc, statusFunc)

		// Bridge gin's flow to net/http: present c.Next() as an http.Handler so
		// httpmw can wrap it with body capture, header scrubbing, and httpsnoop.
		// We reinject the (potentially modified) request back into c so that
		// downstream gin handlers see the request with the request-ID context.
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c.Request = r
			c.Next()
		})

		mw(next).ServeHTTP(c.Writer, c.Request)
	}
}

// NewWithConfig constructs a gin.HandlerFunc directly from a redactlog.Config,
// building the Handler internally. Returns an error if cfg is invalid.
func NewWithConfig(cfg redactlog.Config) (ggin.HandlerFunc, error) {
	h, err := cfg.Build()
	if err != nil {
		return nil, err
	}
	return New(h), nil
}
