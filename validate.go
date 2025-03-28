package jwt

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	BearerSchema = "Bearer"

	authHeaderPart                = 2
	httpClientMaxIdleCon          = 10
	httpClientIdleConnTimeout     = 30 * time.Second
	httpClientTLSHandshakeTimeout = 30 * time.Second
	jwksRefreshInterval           = 24 * time.Hour
	defaultTimeout                = 60 * time.Second
)

type JWKS struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kid string   `json:"kid"`
	X5c []string `json:"x5c"`
}

type JWTOpts struct {
	JwksURL   string
	Audiences []string
}

type JWTValidator struct {
	jwksURL   string
	audiences []string
	jwks      *JWKS
	mutex     *sync.RWMutex
}

func NewJWTValidator(ctx context.Context, opts JWTOpts) *JWTValidator {
	return &JWTValidator{
		jwksURL:   opts.JwksURL,
		audiences: opts.Audiences,
		mutex:     &sync.RWMutex{},
		jwks:      nil,
	}
}

// JWTMiddleware takes a JWTValidator and return a function.
// The returned function takes in and returns a http.Handler.
// The returned http.HandlerFunc is the actual middleware.
func JWTMiddleware(validator *JWTValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.TODO()
			authHeader := r.Header.Get("Authorization")

			if authHeader == "" {
				http.Error(w, "auth header missing", http.StatusUnauthorized)
				return
			}
			parts := strings.SplitN(authHeader, " ", authHeaderPart)
			if len(parts) != authHeaderPart || parts[0] != BearerSchema {
				http.Error(w, "bad auth header format", http.StatusBadRequest)
				return
			}

			tokenStr := parts[1]

			keyFunc := validator.createKeyFunc(ctx)

			// Parse and validate token.
			token, err := jwt.Parse(tokenStr, keyFunc)
			if err != nil {
				http.Error(w, "failed to parse jwt token", http.StatusUnauthorized)
				slog.Error("failed to parse jwt token", "error", err)
				return
			}

			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				if aud, ok := claims["aud"].(string); ok {
					if !Contains(validator.audiences, aud) {
						http.Error(w, "invalid token", http.StatusUnauthorized)
						return
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func parseX5c(x5c string) (*rsa.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(x5c)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	cert, err := x509.ParseCertificate(decoded)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	rsaPublicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to extract public key")
	}

	return rsaPublicKey, nil
}

// Returns a key lookup function function that takes in a jwt token,
// extracts the kid, parses its corresponding x5c and returns it.
func (m *JWTValidator) createKeyFunc(ctx context.Context) func(*jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		if method, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			slog.ErrorContext(ctx, "bad signing method", "method", method)
			return nil, fmt.Errorf("bad singing method")
		}
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("no kid in claim")
		}

		// Lock and read from jwks store.
		m.mutex.RLock()
		defer m.mutex.RUnlock()

		// Check if any of the public keys IDs match the auth header kid.
		// If match, parse and return RSA public key.
		for _, key := range m.jwks.Keys {
			if key.Kid == kid {
				var parseErrs []error
				for _, x5c := range key.X5c {
					pubkey, err := parseX5c(x5c)
					if err != nil {
						parseErrs = append(parseErrs, err)
						slog.Error("kid found but failed to parse x5c", "error", err)
						continue
					}
					return pubkey, nil
				}

				return nil, fmt.Errorf("failed to parse any x5c: %s", parseErrs)
			}
		}
		return nil, fmt.Errorf("signing key not found")
	}
}
