package auth

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/antonybholmes/go-sys"
	"github.com/antonybholmes/go-sys/env"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type (
	TokenType = string

	Permission struct {
		Resource string `json:"resource"`
		Action   string `json:"action"`
	}

	Role struct {
		Name        string        `json:"name"`
		Permissions []*Permission `json:"permissions"`
	}

	AuthUserJwtClaims struct {
		jwt.RegisteredClaims
		UserId          string   `json:"userId"` // the publicId of the user
		Data            string   `json:"data,omitempty"`
		OneTimePasscode string   `json:"otp,omitempty"`
		Scope           []string `json:"scope,omitempty"`
		//Roles           []string    `json:"roles,omitempty"`
		Roles       []*Role   `json:"roles,omitempty"`
		RedirectUrl string    `json:"redirectUrl,omitempty"`
		Type        TokenType `json:"type"`
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

	SupabaseTokenClaims struct {
		jwt.RegisteredClaims
		//Name  string `json:"name"`
		Email string `json:"email"`
	}

	TokenCreator struct {
		secret         *rsa.PrivateKey
		accessTokenTTL time.Duration
		otpTokenTTL    time.Duration
		shortTTL       time.Duration
	}
)

const (
	TokenTypeVerifyEmail   TokenType = "verify_email"
	TokenTypePasswordless  TokenType = "passwordless"
	TokenTypeResetPassword TokenType = "reset_password"
	TokenTypeChangeEmail   TokenType = "change_email"
	TokenTypeRefresh       TokenType = "refresh"
	TokenTypeAccess        TokenType = "access"
	TokenTypeUpdate        TokenType = "update"
	TokenTypeOTP           TokenType = "otp"
	// returns session info such as user and is not used for
	// any type of auth
	TokenTypeSession TokenType = "session"

	JwtClaimSep = " "
	EmailClaim  = "https://edb.rdf-lab.org/email"
)

var (
	ErrInvalidTokenType = errors.New("invalid token type")
)

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

func FormatRole(roleName, resource, action string) string {
	return fmt.Sprintf("%s::%s:%s", roleName, resource, action)
}

func FlattenRole(role *Role) []string {
	ret := make([]string, 0, len(role.Permissions))

	for _, p := range role.Permissions {
		ret = append(ret, FormatRole(role.Name, p.Resource, p.Action))
	}

	return ret
}

// FlattenRoles converts a slice of RolePermissions to a flat slice of strings
// in the format "role:permission"
func FlattenRoles(roles []*Role) []string {
	ret := make([]string, 0, len(roles)*2)

	for _, rp := range roles {
		ret = append(ret, FlattenRole(rp)...)
	}

	return ret
}

func hasRole(roles []*Role, f func(roles *sys.StringSet) bool) bool {
	roleSet := sys.NewStringSet()

	for _, rp := range roles {
		roleSet.ListUpdate(FlattenRole(rp))

	}

	return f(roleSet)
}

func HasSuperRole(roles []*Role) bool {
	return hasRole(roles, func(roles *sys.StringSet) bool {
		return roles.Has(RoleSuper)
	})
}

func HasAdminRole(roles []*Role) bool {
	return hasRole(roles, func(roles *sys.StringSet) bool {
		return roles.Has(RoleAdmin) || roles.Has(RoleSuper)
	})
}

func HasWebLoginInRole(roles []*Role) bool {
	return hasRole(roles, func(roles *sys.StringSet) bool {
		return roles.Has(RoleWebLogin)
	})
}

// Claims are space separated strings to match
// the scope spec and reduce jwt complexity
func MakeClaim(claims []string) string {
	return strings.Join(claims, JwtClaimSep)
}

func NewTokenCreator(secret *rsa.PrivateKey) *TokenCreator {
	return &TokenCreator{secret: secret,
		accessTokenTTL: env.GetMin("ACCESS_TOKEN_TTL_MINS", Ttl15Mins),
		otpTokenTTL:    env.GetMin("OTP_TOKEN_TTL_MINS", Ttl20Mins),
		shortTTL:       env.GetMin("SHORT_TTL_MINS", Ttl10Mins)}
}

func (tc *TokenCreator) SetAccessTokenTTL(ttl time.Duration) *TokenCreator {
	tc.accessTokenTTL = ttl
	return tc
}

func (tc *TokenCreator) SetOTPTokenTTL(ttl time.Duration) *TokenCreator {
	tc.otpTokenTTL = ttl
	return tc
}

func (tc *TokenCreator) RefreshToken(c *gin.Context, user *AuthUser) (string, error) {
	return tc.BasicToken(c,
		user.Id,
		TokenTypeRefresh,
		TtlHour)
}

func (tc *TokenCreator) AccessToken(c *gin.Context, userId string, roles []*Role) (string, error) {

	claims := AuthUserJwtClaims{
		UserId: userId,
		//IpAddr:           ipAddr,
		Type:             TokenTypeAccess,
		Roles:            roles,
		RegisteredClaims: makeDefaultClaimsWithTTL(tc.accessTokenTTL)}

	return tc.BaseToken(claims)
}

func (tc *TokenCreator) UpdateToken(c *gin.Context, publicId string, roles []*Role) (string, error) {

	claims := AuthUserJwtClaims{
		UserId: publicId,
		//IpAddr:           ipAddr,
		Type:             TokenTypeUpdate,
		Roles:            roles,
		RegisteredClaims: makeDefaultClaimsWithTTL(Ttl1Min)}

	return tc.BaseToken(claims)
}

func (tc *TokenCreator) MakeVerifyEmailToken(c *gin.Context, authUser *AuthUser, visitUrl string) (string, error) {
	// return tc.ShortTimeToken(c,
	// 	publicId,
	// 	VERIFY_EMAIL_TOKEN)

	claims := AuthUserJwtClaims{
		UserId:           authUser.Id,
		Data:             authUser.FirstName,
		Type:             TokenTypeVerifyEmail,
		RedirectUrl:      visitUrl,
		RegisteredClaims: makeDefaultClaimsWithTTL(tc.shortTTL),
	}

	return tc.BaseToken(claims)
}

func (tc *TokenCreator) MakeResetPasswordToken(c *gin.Context, user *AuthUser) (string, error) {
	claims := AuthUserJwtClaims{
		UserId: user.Id,
		// include first name to personalize reset
		Data:             user.FirstName,
		Type:             TokenTypeResetPassword,
		OneTimePasscode:  CreateOTP(user),
		RegisteredClaims: makeDefaultClaimsWithTTL(tc.otpTokenTTL)}

	return tc.BaseToken(claims)
}

func (tc *TokenCreator) MakeResetEmailToken(c *gin.Context, user *AuthUser, email *mail.Address) (string, error) {

	claims := AuthUserJwtClaims{
		UserId:           user.Id,
		Data:             email.Address,
		Type:             TokenTypeChangeEmail,
		OneTimePasscode:  CreateOTP(user),
		RegisteredClaims: makeDefaultClaimsWithTTL(tc.otpTokenTTL)}

	return tc.BaseToken(claims)

}

func (tc *TokenCreator) MakePasswordlessToken(c *gin.Context, userId string, redirectUrl string) (string, error) {
	// return tc.ShortTimeToken(c,
	// 	publicId,
	// 	PASSWORDLESS_TOKEN)

	claims := AuthUserJwtClaims{
		UserId: userId,
		Type:   TokenTypePasswordless,
		// This is so the frontend can redirect itself to another page to make
		// the workflow smoother. For example, if on mutations page and it
		// requires sign in, we can pass the page url to the server as the visit
		// url and then it can be encoded in the jwt that is sent back, which
		// the frontend can read and once sign in is validated, it can then change
		// to the visit page. This is so the user is not taken to a sign in or
		// account page because then they have to click on the page they want again
		// which is annoying UI.
		RedirectUrl:      redirectUrl,
		RegisteredClaims: makeDefaultClaimsWithTTL(tc.shortTTL),
	}

	return tc.BaseToken(claims)
}

func (tc *TokenCreator) OTPToken(c *gin.Context, user *AuthUser, tokenType TokenType) (string, error) {
	claims := AuthUserJwtClaims{
		UserId:           user.Id,
		Type:             tokenType,
		OneTimePasscode:  CreateOTP(user),
		RegisteredClaims: makeDefaultClaimsWithTTL(tc.shortTTL),
	}

	return tc.BaseToken(claims)
}

// Generate short lived tokens for one time passcode use.
func (tc *TokenCreator) ShortTimeToken(c *gin.Context,
	publicId string,
	tokenType TokenType) (string, error) {
	return tc.BasicToken(c, publicId, tokenType, tc.shortTTL)
}

func (tc *TokenCreator) BasicToken(c *gin.Context,
	publicId string,
	tokenType TokenType,
	ttl time.Duration) (string, error) {
	claims := AuthUserJwtClaims{
		UserId:           publicId,
		Type:             tokenType,
		RegisteredClaims: makeDefaultClaimsWithTTL(ttl),
	}

	return tc.BaseToken(claims)
}

func (tc *TokenCreator) BaseToken(claims jwt.Claims) (string, error) {

	// Create token with claims
	//token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Generate encoded token and send it as response.
	t, err := token.SignedString(tc.secret)

	if err != nil {
		return "", err
	}

	return t, nil
}

func makeDefaultClaimsWithTTL(ttl time.Duration) jwt.RegisteredClaims {
	return jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl))}
}
