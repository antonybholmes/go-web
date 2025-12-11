package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"net/http"
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

		//Sub   string `json:"sub"`
		Email string `json:"email,omitempty"`
		Name  string `json:"name,omitempty"`
	}

	OIDCVerifier struct {
		Issuer     string
		Audience   string
		JWKS       keyfunc.Keyfunc
		EmailClaim string
		NameClaim  string
	}

	// Define a simple struct to hold only the JWKS URI
	OIDCConfig struct {
		JWKSURI string `json:"jwks_uri"`
	}
)

func NewStandardOIDCVerifier(ctx context.Context,
	issuer string,
	audience string) (*OIDCVerifier, error) {
	return NewOIDCVerifier(ctx, issuer, audience, "email", "name")
}

// NewOIDCVerifier creates a new OIDCVerifier
// issuer: the expected issuer URL
// audience: the expected audience (client ID)
// emailClaim: the claim name for the user's email, useful for Auth0 custom claims which are namespaced
// nameClaim: the claim name for the user's name, useful for Auth0 custom claims which are namespaced
func NewOIDCVerifier(ctx context.Context,
	issuer string,
	audience string,
	emailClaim string,
	nameClaim string) (*OIDCVerifier, error) {
	//jwksURL := issuer + "/.well-known/jwks.json"

	// strip trailing slash for comparison
	issuer = strings.TrimRight(issuer, "/")
	audience = strings.TrimRight(audience, "/")

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
		Issuer:     issuer,
		Audience:   audience,
		JWKS:       kf,
		EmailClaim: emailClaim,
		NameClaim:  nameClaim,
	}, nil
}

func (v *OIDCVerifier) Verify(tokenString string) (*OIDCClaims, error) {
	claims := jwt.MapClaims{}

	log.Debug().Msgf("Verifying token: %s", tokenString)

	token, err := jwt.ParseWithClaims(
		tokenString,
		&claims,
		v.JWKS.Keyfunc,
	)

	log.Debug().Msgf("Parsed token: %v %v", token, err)

	if !token.Valid {
		return nil, auth.NewTokenError("invalid token")
	}

	if err != nil {
		return nil, auth.NewTokenError(fmt.Sprintf("signature/parse error: %v", err))
	}

	issuer, err := claims.GetIssuer()
	if err != nil {
		return nil, auth.NewTokenError(fmt.Sprintf("invalid issuer claim: %v", err))
	}
	issuer = strings.TrimRight(issuer, "/")

	audience, err := claims.GetAudience()
	if err != nil {
		return nil, auth.NewTokenError(fmt.Sprintf("invalid audience claim: %v", err))
	}

	expiresAt, err := claims.GetExpirationTime()
	if err != nil {
		return nil, auth.NewTokenError(fmt.Sprintf("invalid exp claim: %v", err))
	}

	issuedAt, err := claims.GetIssuedAt()
	if err != nil {
		return nil, auth.NewTokenError(fmt.Sprintf("invalid iat claim: %v", err))
	}

	notBefore, err := claims.GetNotBefore()
	if err != nil {
		return nil, auth.NewTokenError(fmt.Sprintf("invalid nbf claim: %v", err))
	}

	email, err := getStringClaim(claims, v.EmailClaim)
	if err != nil {
		return nil, auth.NewTokenError(fmt.Sprintf("invalid email claim: %v", err))
	}

	name, err := getStringClaim(claims, v.NameClaim)
	if err != nil {
		return nil, auth.NewTokenError(fmt.Sprintf("invalid name claim: %v", err))
	}

	oidcClaims := &OIDCClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Audience:  audience,
			ExpiresAt: expiresAt,
			IssuedAt:  issuedAt,
			NotBefore: notBefore,
		},
		Email: email,
		Name:  name,
	}

	return v.verifyClaims(oidcClaims)
}

// once claims are created, verify them
func (v *OIDCVerifier) verifyClaims(oidcClaims *OIDCClaims) (*OIDCClaims, error) {

	// issuer match
	log.Debug().Msgf("Verifying token issuer: expected=%s, got=%s", v.Issuer, oidcClaims.Issuer)

	if oidcClaims.Issuer != v.Issuer {
		return nil, auth.NewTokenError("invalid issuer")
	}

	// audience match also including stripping trailing slashes
	// since Auth0 uses them but Cognito does not

	if v.Audience != "" {
		found := false

		for _, aud := range oidcClaims.Audience {
			aud = strings.TrimRight(aud, "/")

			if aud == v.Audience {
				found = true
				break
			}
		}

		if !found {
			return nil, auth.NewTokenError("invalid audience")
		}
	}

	if oidcClaims.Email == "" {
		return nil, auth.NewTokenError("missing email claim")
	}

	if oidcClaims.Name == "" {
		return nil, auth.NewTokenError("missing name claim")
	}

	// expiry match
	if oidcClaims.ExpiresAt == nil {
		return nil, auth.NewTokenError("missing exp claim")
	}

	if time.Now().UTC().After(oidcClaims.ExpiresAt.Time) {
		return nil, auth.NewTokenError("token expired")
	}

	return oidcClaims, nil
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

func getStringClaim(claims jwt.MapClaims, key string) (string, error) {
	val, ok := claims[key]
	if !ok {
		return "", fmt.Errorf("missing claim: %s", key)
	}
	s, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("claim %s is not a string", key)
	}
	return s, nil
}
