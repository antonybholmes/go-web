package oauth2

import (
	"context"
	"encoding/json"
	"fmt"

	"net/http"
	"slices"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/antonybholmes/go-sys/log"
	"github.com/antonybholmes/go-web/auth"
	"github.com/golang-jwt/jwt/v5"
)

type (
	OIDCClaims struct {
		// You can add more standard claims if needed
		jwt.RegisteredClaims

		Sub   string `json:"sub"`
		Email string `json:"email,omitempty"`
		Name  string `json:"name,omitempty"`
	}

	OIDCVerifier struct {
		Issuer   string
		Audience string
		JWKS     keyfunc.Keyfunc
	}

	// Define a simple struct to hold only the JWKS URI
	OIDCConfig struct {
		JWKSURI string `json:"jwks_uri"`
	}
)

// issuer: the expected issuer URL
// audience: the expected audience (client ID)
func NewOIDCVerifier(ctx context.Context, issuer string, audience string) (*OIDCVerifier, error) {
	//jwksURL := issuer + "/.well-known/jwks.json"

	oidcConfigURL := issuer + "/.well-known/openid-configuration"

	log.Debug().Msgf("Fetching OIDC config from: %s", oidcConfigURL)

	cfg, err := fetchOIDCConfig(ctx, oidcConfigURL)

	if err != nil {
		return nil, auth.NewTokenError(fmt.Sprintf("failed to fetch OIDC config: %v", err))
	}

	// Create Keyfunc with background refresh
	kf, err := keyfunc.NewDefaultCtx(ctx, []string{cfg.JWKSURI})
	if err != nil {
		return nil, auth.NewTokenError(fmt.Sprintf("failed to create JWKS keyfunc: %v", err))
	}

	return &OIDCVerifier{
		Issuer:   issuer,
		Audience: audience,
		JWKS:     kf,
	}, nil
}

func (v *OIDCVerifier) Verify(tokenString string) (*OIDCClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&OIDCClaims{},
		v.JWKS.Keyfunc,
	)

	if err != nil {
		return nil, auth.NewTokenError(fmt.Sprintf("signature/parse error: %v", err))
	}

	if !token.Valid {
		return nil, auth.NewTokenError("invalid token")
	}

	claims := token.Claims.(*OIDCClaims)

	// issuer match
	if claims.Issuer != v.Issuer {
		return nil, auth.NewTokenError("invalid issuer")
	}

	// audience match
	if v.Audience != "" && !slices.Contains(claims.Audience, v.Audience) {
		return nil, auth.NewTokenError("invalid audience")
	}

	// expiry match
	if claims.ExpiresAt == nil {
		return nil, auth.NewTokenError("missing exp claim")
	}

	if time.Now().UTC().After(claims.ExpiresAt.Time) {
		return nil, auth.NewTokenError("token expired")
	}

	return claims, nil
}

// Fetches the OIDC configuration from the given URL and extracts the JWKS URI.
// so we don't have to hardcode it.
func fetchOIDCConfig(ctx context.Context, url string) (*OIDCConfig, error) {

	// Create an HTTP request with context
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)

	if err != nil {
		return nil, err
	}

	// Execute the request
	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	// Decode the JSON response
	var cfg OIDCConfig

	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, err
	}

	// Make sure the JWKS URI exists
	if cfg.JWKSURI == "" {
		return nil, auth.NewTokenError("jwks_uri not found in OIDC configuration")
	}

	//log.Debug().Msgf("Fetched JWKS URI: %s", cfg.JWKSURI)

	// Return the JWKS URI
	return &cfg, nil
}
