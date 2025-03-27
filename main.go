package jwt

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
)

func main() {

	ctx := context.Background()
	jwtOpts := JWTOpts{
		JwksURL: "https://login.microsoftonline.com/9b5ff18e-53c0-45a2-8bc2-9c0c8f60b2c6/discovery/v2.0/keys",
		Audiences: []string{
			"api://8cfd806f-3d93-4c3e-87a1-db7002b142a1",
		},
	}
	validator := NewJWTValidator(ctx, jwtOpts)

	// Start gofunc for synchronizing keys
	validator.StartSync(ctx)

	// Set up a server
	mux := http.NewServeMux()

	// Create middleware
	jwtMiddleware := JWTMiddleware(validator)

	// Apply middleware to handler
	mux.Handle("/ping", jwtMiddleware(http.HandlerFunc(pingHandler)))

	if err := http.ListenAndServe(":8080", nil); err != nil {
		slog.Error("server failed", "error", err)
	}
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "pong")
}
