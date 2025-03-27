package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

func (m *JWTValidator) StartSync(ctx context.Context) {
	go func() {

		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for {
			slog.Info("fetching new keys")
			if err := m.synchronizeKeys(ctx); err != nil {
				slog.Error("failed to fetch remote keys", "error", err)
			}

			select {
			case <-ctx.Done():
				slog.Info("jwks sync stopped")
				return
			case <-ticker.C:
				continue
			}
		}
	}()
}

func NewJWTValidator(ctx context.Context, opts JWTOpts) *JWTValidator {
	return &JWTValidator{
		jwksURL:   opts.JwksURL,
		audiences: opts.Audiences,
		mutex:     &sync.RWMutex{},
		jwks:      nil,
	}
}

func fetchRemoteJWKS(ctx context.Context, jwksURL string) (JWKS, error) {
	slog.DebugContext(ctx, "Starting fetchRemoteJWKS")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return JWKS{}, fmt.Errorf("crafting request to %s failed with %w", jwksURL, err)
	}

	httpClient := &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        httpClientMaxIdleCon,
			IdleConnTimeout:     httpClientIdleConnTimeout,
			DisableCompression:  true,
			TLSHandshakeTimeout: httpClientTLSHandshakeTimeout,
		},
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		slog.DebugContext(ctx, "failed request", "url", jwksURL, "error", err)
		return JWKS{}, fmt.Errorf("request to %s failed with %w", jwksURL, err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	var jwks JWKS

	err = json.NewDecoder(resp.Body).Decode(&jwks)
	if err != nil {
		slog.DebugContext(ctx, "failed to decode json response from JWKS url", "error", err)
		return JWKS{}, fmt.Errorf("failed to decode json response %w", err)
	}

	slog.DebugContext(ctx, "fetchRemoteJWKS done")

	return jwks, nil
}

func (m *JWTValidator) synchronizeKeys(ctx context.Context) error {
	slog.DebugContext(ctx, "Refreshing JWKS keys")

	newJWKS, err := fetchRemoteJWKS(ctx, m.jwksURL)
	if err != nil {
		return fmt.Errorf("failed to fetch remote keys: %w", err)
	}

	m.mutex.Lock()
	m.jwks = &newJWKS
	m.mutex.Unlock()

	slog.DebugContext(ctx, "JWKS keys refreshed successfully")

	return nil
}
