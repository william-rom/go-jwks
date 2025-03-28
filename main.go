package jwt

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
)

func main() {
	ctx := context.Background()

	// Configure jwks fetching opts.
	jwksOpts := JWKSFetcherOpts{
		baseURL: "https://login.microsoftonline.com/9b5ff18e-53c0-45a2-8bc2-9c0c8f60b2c6",
	}
	// Set up new jwks fetcher.
	fetcher := NewJWKSFetcher(jwksOpts)

	// Start gofunc for synchronizing keys.
	fetcher.Start(ctx)

	// Set audience used for validation.
	audiences := []string{
		"api://8cfd806f-3d93-4c3e-87a1-db7002b142a1",
	}

	// Create a JWT validator instance.
	validator := NewJWTValidator(fetcher, audiences)

	// Create the http.Handler middleware.
	jwtMiddleware := JWTMiddleware(validator)

	mux := http.NewServeMux()

	// Apply middleware to handler.
	mux.Handle("/ping", jwtMiddleware(http.HandlerFunc(pingHandler)))

	if err := http.ListenAndServe(":8080", mux); err != nil {
		slog.Error("server failed", "error", err)
	}
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "pong")
}
