package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"slices"
	"strings"
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
	Keys []JSONWebKey `json:"keys"`
}
type JSONWebKey struct {
	Kid string `json:"kid"`           // Key ID (required for lookup)
	Kty string `json:"kty"`           // Key Type (e.g., "RSA", "EC") (Required)
	Use string `json:"use,omitempty"` // Key Use (e.g., "sig", "enc") (Optional)
	Alg string `json:"alg,omitempty"` // Algorithm (Optional)

	// RSA-specific parameters (Base64urlUInt encoding)
	N string `json:"n,omitempty"` // Modulus
	E string `json:"e,omitempty"` // Public Exponent

	// EC-specific parameters (Base64url encoding for X/Y)
	Crv string `json:"crv,omitempty"` // Curve (e.g., "P-256")
	X   string `json:"x,omitempty"`   // X Coordinate
	Y   string `json:"y,omitempty"`   // Y Coordinate

	// X.509 Certificate Chain (Standard Base64 encoding)
	X5c []string `json:"x5c,omitempty"` // Optional, can be used as fallback or primary source
}

type JWTValidator struct {
	JWKSFetcher  *JWKSFetcher
	audiences    []string
	validMethods []string
}

func NewJWTValidator(fetcher *JWKSFetcher, audiences []string, validMethods []string) *JWTValidator {
	return &JWTValidator{
		JWKSFetcher:  fetcher,
		audiences:    audiences,
		validMethods: validMethods,
	}
}

// JWTMiddleware takes a JWTValidator and return a function.
// The returned function takes in and returns a http.Handler.
// The returned http.HandlerFunc is the actual middleware.
func JWTMiddleware(validator *JWTValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

			keyFunc := validator.createKeyFunc()

			// Parse and validate token.
			token, err := jwt.Parse(tokenStr, keyFunc, jwt.WithValidMethods(validator.validMethods))
			if err != nil {
				msg := "failed to parse jwt token"
				http.Error(w, msg, http.StatusUnauthorized)
				slog.Error(msg, "error", err)
				return
			}

			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				validAud := false
				// Check if aud exists
				if audClaim, ok := claims["aud"]; ok {

					// Single aud
					if audStr, ok := claims["aud"].(string); ok {
						if slices.Contains(validator.audiences, audStr) {
							validAud = true
						}
						// multiple auds
					} else if audSlice, ok := audClaim.([]interface{}); ok {
						for _, audx := range audSlice {
							if audStr, ok := audx.(string); ok {
								if slices.Contains(validator.audiences, audStr) {
									validAud = true
									break
								}
							}
						}

					}
				}
				if !validAud {
					slog.Error("token audience validation failed", "aud", claims["aud"])
					http.Error(w, "invalid token", http.StatusUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
			} else {
				slog.Warn("token claims parsed but invalid", "claims", claims, "valid", token.Valid)
			}
		})
	}
}

// Parse JWK. Attempt both RSA and EC parsing. Return the public key.
func parseKey(jwk *JSONWebKey) (interface{}, error) {
	switch jwk.Kty {
	case "RSA":
		if jwk.N != "" && jwk.E != "" {
			// Decode RSA param n
			nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
			if err != nil {
				return nil, fmt.Errorf("failed to decode RSA modulus 'n': %w", err)
			}
			n := new(big.Int).SetBytes(nBytes)
			// Decode RSA param e
			eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
			if err != nil {
				return nil, fmt.Errorf("failed to decode RSA modulus 'e': %w", err)
			}
			// Might not need to be big?
			e := new(big.Int).SetBytes(eBytes)
			if n.BitLen() == 0 || e.BitLen() == 0 {
				return nil, fmt.Errorf("big inting failed")
			}
			// TODO: clean up
			return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
		} else {
			return nil, fmt.Errorf("missing N and/or E param")
		}
	//TODO: add EC support
	case "EC":
		return nil, fmt.Errorf("EC not yet supported")
	default:
		return nil, fmt.Errorf("method not supported: %s", jwk.Kty)
	}
}

// Returns a key lookup function function that takes in a jwt token,
// A KeyFunc return (interface{}, error) where the interface may be a single key or a verificationKeySet with many keys.
func (v *JWTValidator) createKeyFunc() func(*jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("no kid in claim")
		}

		// Lock and read from jwks store.
		v.JWKSFetcher.mutex.RLock()
		defer v.JWKSFetcher.mutex.RUnlock()

		// Check if any of the public keys IDs match the auth header kid.
		// If match, parse and return RSA public key.
		for _, key := range v.JWKSFetcher.jwks.Keys {
			if key.Kid == kid {
				pubkey, err := parseKey(&key)
				if err != nil {
					slog.Error("failed to parse public key from JWK", "error", err)
					return nil, fmt.Errorf("failed to parse key for kid %s: %w", kid, err)
				}
				if pubkey == nil {
					return nil, fmt.Errorf("key found for kid %s, but parsing resulted in nil key", key)
				}
				return pubkey, nil
			}
		}
		return nil, fmt.Errorf("signing key not found")
	}
}

func createDiscoveryURL(baseURL string) string {
	baseURL = strings.TrimSuffix(baseURL, "/")
	disoveryPath := "/discovery/v2.0/keys"

	return baseURL + disoveryPath
}
