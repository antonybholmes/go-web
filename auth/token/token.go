package token

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/antonybholmes/go-sys/env"
	"github.com/antonybholmes/go-web/auth"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type (
	//TokenType = string

	// Permission struct {
	// 	Resource string `json:"resource"`
	// 	Action   string `json:"action"`
	// }

	TokenRequest struct {
		ClientID     string           `json:"client_id"     form:"client_id"`
		ClientSecret string           `json:"client_secret" form:"client_secret"`
		Audience     jwt.ClaimStrings `json:"audience"      form:"audience"`
		Type         string           `json:"type"          form:"type"`
		GrantType    string           `json:"grant_type"    form:"grant_type"`
	}

	AuthUserJwtClaims struct {
		jwt.RegisteredClaims
		//UserId          string   `json:"id"` // the publicId of the user
		Data            string   `json:"data,omitempty"`
		OneTimePasscode string   `json:"otp,omitempty"`
		Scope           []string `json:"scope,omitempty"`
		//Roles           []string    `json:"roles,omitempty"`
		//Roles       []*Role   `json:"roles,omitempty"`
		Permissions        []string `json:"p,omitempty"`
		PermissionsVersion int      `json:"pv,omitempty"`
		RedirectUrl        string   `json:"redirectUrl,omitempty"`
		Type               string   `json:"t"`
	}

	Auth0TokenClaims struct {
		jwt.RegisteredClaims
		Name  string `json:"https://edb.rdf-lab.org/name"`
		Email string `json:"https://edb.rdf-lab.org/email"`
	}

	ClerkTokenClaims struct {
		jwt.RegisteredClaims
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	SupabaseUserMetadata struct {
		DisplayName string `json:"display_name"`
		FullName    string `json:"full_name"`
		AvatarUrl   string `json:"avatar_url"`
	}

	SupabaseTokenClaims struct {
		jwt.RegisteredClaims
		//Name  string `json:"name"`
		Email        string               `json:"email"`
		UserMetadata SupabaseUserMetadata `json:"user_metadata"`
	}

	TokenError struct {
		s string
	}

	TokenSigner interface {
		Sign(claims jwt.Claims) (string, error)
	}

	TokenCreator struct {
		tokenSigner    TokenSigner
		accessTokenTTL time.Duration
		otpTokenTTL    time.Duration
		shortTTL       time.Duration
	}

	RSATokenSigner struct {
		secret *rsa.PrivateKey
	}

	ES256TokenSigner struct {
		secret *ecdsa.PrivateKey
	}
)

const (
	TokenTypeVerifyEmail   = "verify_email"
	TokenTypePasswordless  = "passwordless"
	TokenTypeResetPassword = "reset_password"
	TokenTypeChangeEmail   = "change_email"
	TokenTypeRefresh       = "refresh"
	TokenTypeAccess        = "access"
	TokenTypeUpdate        = "update"
	TokenTypeOTP           = "otp"
	// returns session info such as user and is not used for
	// any type of auth
	TokenTypeSession = "session"

	JwtClaimSep = " "
	EmailClaim  = "https://edb.rdf-lab.org/email"

	PermissionsVersion = 1
)

var (
	ErrInvalidTokenType = NewTokenError("invalid token type")
)

func NewTokenError(s string) *TokenError {
	return &TokenError{s}
}

func (e *TokenError) Error() string {
	return fmt.Sprintf("token error: %s", e.s)
}

func ParseToken(c *gin.Context) (string, error) {
	// Get the token from the "Authorization" header
	authHeader := c.GetHeader("Authorization")

	if authHeader == "" {
		return "", NewTokenError("authorization header missing")
	}

	// Split the token (format: "Bearer <token>")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	if tokenString == authHeader {
		return "", NewTokenError("malformed token")
	}

	return tokenString, nil
}

//type RoleMap map[string][]string

// type JwtResetPasswordClaims struct {
// 	Username string `json:"username"`
// 	JwtCustomClaims
// }

// type JwtUpdateEmailClaims struct {
// 	Email string `json:"email"`
// 	JwtCustomClaims
// }

// func TokenTypeString(t TokenType) string {
// 	switch t {
// 	case TOKEN_TYPE_VERIFY_EMAIL:
// 		return "verify_email_token"
// 	case TOKEN_TYPE_PASSWORDLESS:
// 		return "passwordless_token"
// 	case TOKEN_TYPE_RESET_PASSWORD:
// 		return "reset_password_token"
// 	case TOKEN_TYPE_ACCESS:
// 		return "access_token"
// 	case TOKEN_TYPE_REFRESH:
// 		return "refresh_token"
// 	default:
// 		return "other"
// 	}
// }

// Claims are space separated strings to match
// the scope spec and reduce jwt complexity
func MakeClaim(claims []string) string {
	return strings.Join(claims, JwtClaimSep)
}

func makeDefaultClaimsWithTTL(sub string, aud jwt.ClaimStrings, ttl time.Duration) jwt.RegisteredClaims {
	return jwt.RegisteredClaims{Subject: sub, Audience: aud, ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl))}
}

func NewTokenCreator(tokenSigner TokenSigner) *TokenCreator {
	return &TokenCreator{tokenSigner: tokenSigner,
		accessTokenTTL: env.GetMin("ACCESS_TOKEN_TTL_MINS", auth.Ttl15Mins),
		otpTokenTTL:    env.GetMin("OTP_TOKEN_TTL_MINS", auth.Ttl20Mins),
		shortTTL:       env.GetMin("SHORT_TTL_MINS", auth.Ttl10Mins)}
}

func (tc *TokenCreator) SetAccessTokenTTL(ttl time.Duration) *TokenCreator {
	tc.accessTokenTTL = ttl
	return tc
}

func (tc *TokenCreator) SetOTPTokenTTL(ttl time.Duration) *TokenCreator {
	tc.otpTokenTTL = ttl
	return tc
}

func (tc *TokenCreator) RefreshToken(c *gin.Context, user *auth.AuthUser, audience jwt.ClaimStrings) (string, error) {
	return tc.BasicToken(c,
		user.Id,
		audience,
		TokenTypeRefresh,
		auth.TtlHour)
}

// func addPermissionsToClaims(token *AuthUserJwtClaims, roles []*Role) {
// 	token.Permissions = RolesToPermissions(roles)
// 	token.PermissionsVersion = PermissionsVersion
// }

func (tc *TokenCreator) AccessToken(c *gin.Context,
	userId string,
	audience jwt.ClaimStrings,
	roles []*auth.Role) (string, error) {

	// claims := AuthUserJwtClaims{
	// 	UserId: userId,
	// 	//IpAddr:           ipAddr,
	// 	Type: TokenTypeAccess,
	// 	//Roles:            roles,
	// 	RegisteredClaims: makeDefaultClaimsWithTTL(tc.accessTokenTTL)}

	// addPermissionsToClaims(&claims, roles)

	// return tc.BaseToken(claims)

	return tc.AccessTokenUsingPermissions(c, userId, audience, auth.RolesToPermissions(roles))
}

// If we are creating a new access token using the permissions of the current
// token
func (tc *TokenCreator) AccessTokenUsingPermissions(c *gin.Context, userId string, audience jwt.ClaimStrings, permissions []string) (string, error) {

	claims := AuthUserJwtClaims{

		//IpAddr:           ipAddr,
		Type:               TokenTypeAccess,
		Permissions:        permissions,
		PermissionsVersion: PermissionsVersion,
		RegisteredClaims:   makeDefaultClaimsWithTTL(userId, audience, tc.accessTokenTTL)}

	return tc.tokenSigner.Sign(claims)
}

func (tc *TokenCreator) UpdateToken(c *gin.Context, userId string, audience jwt.ClaimStrings, roles []*auth.Role) (string, error) {

	claims := AuthUserJwtClaims{

		//IpAddr:           ipAddr,
		Type:               TokenTypeUpdate,
		Permissions:        auth.RolesToPermissions(roles),
		PermissionsVersion: PermissionsVersion,
		RegisteredClaims:   makeDefaultClaimsWithTTL(userId, audience, auth.Ttl1Min)}

	return tc.tokenSigner.Sign(claims)
}

func (tc *TokenCreator) MakeVerifyEmailToken(c *gin.Context, authUser *auth.AuthUser, audience jwt.ClaimStrings, visitUrl string) (string, error) {
	// return tc.ShortTimeToken(c,
	// 	publicId,
	// 	VERIFY_EMAIL_TOKEN)

	claims := AuthUserJwtClaims{
		Data:             authUser.Name,
		Type:             TokenTypeVerifyEmail,
		RedirectUrl:      visitUrl,
		RegisteredClaims: makeDefaultClaimsWithTTL(authUser.Id, audience, tc.shortTTL),
	}

	return tc.tokenSigner.Sign(claims)
}

func (tc *TokenCreator) MakeResetPasswordToken(c *gin.Context, user *auth.AuthUser, audience jwt.ClaimStrings) (string, error) {
	claims := AuthUserJwtClaims{
		// include first name to personalize reset
		Data:             user.Name,
		Type:             TokenTypeResetPassword,
		OneTimePasscode:  auth.CreateOTP(user),
		RegisteredClaims: makeDefaultClaimsWithTTL(user.Id, audience, tc.otpTokenTTL)}

	return tc.tokenSigner.Sign(claims)
}

func (tc *TokenCreator) MakeResetEmailToken(c *gin.Context, user *auth.AuthUser, audience jwt.ClaimStrings, email *mail.Address) (string, error) {

	claims := AuthUserJwtClaims{
		Data:             email.Address,
		Type:             TokenTypeChangeEmail,
		OneTimePasscode:  auth.CreateOTP(user),
		RegisteredClaims: makeDefaultClaimsWithTTL(user.Id, audience, tc.otpTokenTTL)}

	return tc.tokenSigner.Sign(claims)

}

func (tc *TokenCreator) MakePasswordlessToken(c *gin.Context, userId string, audience jwt.ClaimStrings, redirectUrl string) (string, error) {
	// return tc.ShortTimeToken(c,
	// 	publicId,
	// 	PASSWORDLESS_TOKEN)

	claims := AuthUserJwtClaims{
		Type: TokenTypePasswordless,
		// This is so the frontend can redirect itself to another page to make
		// the workflow smoother. For example, if on mutations page and it
		// requires sign in, we can pass the page url to the server as the visit
		// url and then it can be encoded in the jwt that is sent back, which
		// the frontend can read and once sign in is validated, it can then change
		// to the visit page. This is so the user is not taken to a sign in or
		// account page because then they have to click on the page they want again
		// which is annoying UI.
		RedirectUrl:      redirectUrl,
		RegisteredClaims: makeDefaultClaimsWithTTL(userId, audience, tc.shortTTL),
	}

	return tc.tokenSigner.Sign(claims)
}

func (tc *TokenCreator) OTPToken(c *gin.Context, user *auth.AuthUser, audience jwt.ClaimStrings, tokenType string) (string, error) {
	claims := AuthUserJwtClaims{
		Type:             tokenType,
		OneTimePasscode:  auth.CreateOTP(user),
		RegisteredClaims: makeDefaultClaimsWithTTL(user.Id, audience, tc.shortTTL),
	}

	return tc.tokenSigner.Sign(claims)
}

// Generate short lived tokens for one time passcode use.
func (tc *TokenCreator) ShortTimeToken(c *gin.Context,
	publicId string,
	audience jwt.ClaimStrings,
	tokenType string) (string, error) {
	return tc.BasicToken(c, publicId, audience, tokenType, tc.shortTTL)
}

func (tc *TokenCreator) BasicToken(c *gin.Context,
	userId string,
	audience jwt.ClaimStrings,
	tokenType string,
	ttl time.Duration) (string, error) {
	claims := AuthUserJwtClaims{
		Type:             tokenType,
		RegisteredClaims: makeDefaultClaimsWithTTL(userId, audience, ttl),
	}

	return tc.tokenSigner.Sign(claims)
}

func NewRSATokenSigner(secret *rsa.PrivateKey) *RSATokenSigner {
	return &RSATokenSigner{secret: secret}
}

func (tc *RSATokenSigner) Sign(claims jwt.Claims) (string, error) {

	// Create token with claims
	//token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	//token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	// Generate encoded token and send it as response.
	t, err := token.SignedString(tc.secret)

	if err != nil {
		return "", err
	}

	return t, nil
}

func NewES256TokenSigner(secret *ecdsa.PrivateKey) *ES256TokenSigner {
	return &ES256TokenSigner{secret: secret}
}

func (tc *ES256TokenSigner) Sign(claims jwt.Claims) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	// Generate encoded token and send it as response.
	t, err := token.SignedString(tc.secret)

	if err != nil {
		return "", err
	}

	return t, nil
}
