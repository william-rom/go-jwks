package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	jwtpkg "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// generateRSAKey creates a new RSA private key.
func generateRSAKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}
	return privateKey, nil
}

// // generateSelfSignedCert creates a basic self-signed X.509 certificate
// // containing the given public key. This is needed because the original
// // `parseX5c` expects a certificate, not just a public key.
// func generateSelfSignedCert(key *rsa.PrivateKey) ([]byte, error) {
// 	template := x509.Certificate{
// 		SerialNumber: big.NewInt(1),
// 		Subject: pkix.Name{
// 			Organization: []string{"Test Org"},
// 		},
// 		NotBefore: time.Now(),
// 		NotAfter:  time.Now().Add(time.Hour * 24 * 365), // 1 year validity
//
// 		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
// 		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
// 		BasicConstraintsValid: true,
// 	}
//
// 	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create certificate: %w", err)
// 	}
//
// 	return derBytes, nil
// }

// generateTestJWT creates a JWT for testing.
func generateTestJWT(signingKey *rsa.PrivateKey, kid, audience string, expiry time.Time, method jwtpkg.SigningMethod) (string, error) {
	token := jwtpkg.New(method)
	token.Header["kid"] = kid
	claims := token.Claims.(jwtpkg.MapClaims)
	claims["aud"] = audience
	claims["exp"] = expiry.Unix()
	claims["iat"] = time.Now().Unix()
	claims["nbf"] = time.Now().Unix()

	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return tokenString, nil
}

// --- Test ---

func TestJWTMiddleware(t *testing.T) {
	//  Generate Keys
	signingKey, err := generateRSAKey()
	assert.NoError(t, err, "Failed to generate signing key")

	invalidSigningKey, err := generateRSAKey()
	assert.NoError(t, err, "Failed to generate invalid signing key")

	// Setup Static JWKS
	kid := "test-kid-12345"
	nBytes := signingKey.PublicKey.N.Bytes()
	nBase64URL := base64.RawURLEncoding.EncodeToString(nBytes)

	eInt := signingKey.PublicKey.E
	eBigInt := big.NewInt(int64(eInt))
	eBytes := eBigInt.Bytes()
	eBase64URL := base64.RawURLEncoding.EncodeToString(eBytes)

	staticJWKS := &JWKS{
		Keys: []JSONWebKey{
			{
				Kid: kid,
				Kty: "RSA",
				// X5c: []string{certX5C}, // Use the base64 encoded certificate DER
				E: eBase64URL,
				//N: "iQ745_U-vjkxPblaw6phBpe08fC42mpcrS4pcr15HiyZQyQV-BFcEVyLwPdsz3ulMRN7OB_UMfCcPBHqOjguejoab6hyJFVVMw_epP4a3SpQN9qaCbnqaSxgSGiqSq663g3TjsF_Wu1m9L41eNoF6Yvh5kULMd6lqjY0LPO5ZZxaQFLtIHahoJKMvYy1BTS0VYcNsXTjxkgUEL6Vc8GV5vaClbnY3VA2hLbXC1SGJWjVGdYXhkuck2tHr58u87MPEaQ33C6YfyISZKsdumF5bTCcIH75jjC3WbMVOLgWg5w0MSiHOFyI76Ihxbb0nRicEuao0WzO9AS7HJ7L24FHFQ",
				N: nBase64URL,
			},
		},
	}

	// Set up a dummy JWKSFetcher with preset keys.
	minimalFetcher := &JWKSFetcher{
		jwks:  staticJWKS,
		mutex: &sync.RWMutex{},
	}

	// Setup Validator.
	audience := "api://my-test-api"
	validator := NewJWTValidator(minimalFetcher, []string{audience}, []string{jwtpkg.SigningMethodRS256.Name})

	// Setup Middleware
	jwtMiddleware := JWTMiddleware(validator)

	// Test Handler
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	testHandler := jwtMiddleware(nextHandler) // Apply middleware

	// --- Test Cases ---
	t.Run("Valid JWT", func(t *testing.T) {
		// Generate a valid JWT token to be used as auth header.
		validToken, err := generateTestJWT(signingKey, kid, audience, time.Now().Add(time.Hour), jwtpkg.SigningMethodRS256)
		assert.NoError(t, err)

		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", validToken))
		recorder := httptest.NewRecorder()

		testHandler.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Code, "Expected status OK for valid token")
		assert.Equal(t, "OK", recorder.Body.String(), "Expected 'OK' body for valid token")
	})

	t.Run("Invalid JWT - Bad Signature", func(t *testing.T) {
		// Generate a token signed with the WRONG key, but using the correct kid
		invalidToken, err := generateTestJWT(invalidSigningKey, kid, audience, time.Now().Add(time.Hour), jwtpkg.SigningMethodRS256)
		assert.NoError(t, err)

		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", invalidToken))
		recorder := httptest.NewRecorder()

		testHandler.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusUnauthorized, recorder.Code, "Expected status Unauthorized for invalid signature")
		assert.Contains(t, recorder.Body.String(), "failed to parse jwt token", "Expected parsing error message") // The library wraps signature errors
	})

	t.Run("Invalid JWT - Wrong Audience", func(t *testing.T) {
		wrongAudToken, err := generateTestJWT(signingKey, kid, "api://wrong-audience", time.Now().Add(time.Hour), jwtpkg.SigningMethodRS256)
		assert.NoError(t, err)

		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", wrongAudToken))
		recorder := httptest.NewRecorder()

		testHandler.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusUnauthorized, recorder.Code, "Expected status Unauthorized for wrong audience")
		assert.Contains(t, recorder.Body.String(), "invalid token", "Expected invalid token message for wrong audience")
	})

	t.Run("Invalid JWT - Expired", func(t *testing.T) {
		// Generate an expired token
		expiredToken, err := generateTestJWT(signingKey, kid, audience, time.Now().Add(-time.Hour), jwtpkg.SigningMethodRS256) // Expired 1 hour ago
		assert.NoError(t, err)

		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", expiredToken))
		recorder := httptest.NewRecorder()

		testHandler.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusUnauthorized, recorder.Code, "Expected status Unauthorized for expired token")
		assert.Contains(t, recorder.Body.String(), "failed to parse jwt token", "Expected parsing error message for expired token") // jwt-go includes expiry check in Parse
	})
}
