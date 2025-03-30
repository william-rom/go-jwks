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

type JWKSFetcher struct {
	wellKnowURL   string
	jwks          *JWKS
	mutex         *sync.RWMutex
	fetchInterval time.Duration
	httpClient    *http.Client
}

type JWKSFetcherOpts struct {
	baseURL       string
	fetchInterval time.Duration
}

func NewJWKSFetcher(opts JWKSFetcherOpts) *JWKSFetcher {
	if opts.fetchInterval == 0 {
		opts.fetchInterval = 24 * time.Hour
	}

	// TODO: make opts customizable
	httpClient := &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        httpClientMaxIdleCon,
			IdleConnTimeout:     httpClientIdleConnTimeout,
			DisableCompression:  true,
			TLSHandshakeTimeout: httpClientTLSHandshakeTimeout,
		},
	}

	return &JWKSFetcher{
		wellKnowURL:   createDiscoveryURL(opts.baseURL),
		mutex:         &sync.RWMutex{},
		jwks:          nil,
		fetchInterval: opts.fetchInterval,
		httpClient:    httpClient,
	}
}

// Start synchronization of JWKS into in-memory store.
func (f *JWKSFetcher) Start(ctx context.Context) {
	go func() {
		slog.Info("performing intitial fetch")
		if err := f.synchronizeKeys(ctx); err != nil {
			slog.Error("initial JWKS fetch failed", "error", err)
		}

		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for {
			slog.Info("fetching new keys")
			if err := f.synchronizeKeys(ctx); err != nil {
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

func (f *JWKSFetcher) fetchRemoteJWKS(ctx context.Context, jwksURL string) (JWKS, error) {
	slog.DebugContext(ctx, "Starting fetchRemoteJWKS")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return JWKS{}, fmt.Errorf("crafting request to %s failed with %w", jwksURL, err)
	}

	resp, err := f.httpClient.Do(req)
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

func (f *JWKSFetcher) synchronizeKeys(ctx context.Context) error {
	slog.DebugContext(ctx, "Refreshing JWKS keys")

	newJWKS, err := f.fetchRemoteJWKS(ctx, f.wellKnowURL)
	if err != nil {
		return fmt.Errorf("failed to fetch remote keys: %w", err)
	}

	f.mutex.Lock()
	f.jwks = &newJWKS
	f.mutex.Unlock()

	slog.DebugContext(ctx, "JWKS keys refreshed successfully")

	return nil
}
