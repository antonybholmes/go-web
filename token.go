package auth

import (
	"crypto/rsa"
	"net/mail"
	"strings"
	"time"

	"github.com/antonybholmes/go-sys/env"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

type TokenType = uint

const (
	VERIFY_EMAIL_TOKEN   TokenType = 1
	PASSWORDLESS_TOKEN   TokenType = 2
	RESET_PASSWORD_TOKEN TokenType = 3
	CHANGE_EMAIL_TOKEN   TokenType = 4
	REFRESH_TOKEN        TokenType = 5
	ACCESS_TOKEN         TokenType = 6
	OTP_TOKEN            TokenType = 7
)

// type TokenType = string

// const (
// 	TOKEN_TYPE_VERIFY_EMAIL   TokenType = "verify_email"
// 	TOKEN_TYPE_PASSWORDLESS   TokenType = "passwordless"
// 	TOKEN_TYPE_RESET_PASSWORD TokenType = "reset_password"
// 	TOKEN_TYPE_CHANGE_EMAIL   TokenType = "change_email"
// 	TOKEN_TYPE_REFRESH        TokenType = "refresh"
// 	TOKEN_TYPE_ACCESS         TokenType = "access"
// 	TOKEN_TYPE_OTP            TokenType = "otp"
// )

const (
	TTL_YEAR    time.Duration = time.Hour * 24 * 365
	TTL_30_DAYS time.Duration = time.Hour * 24 * 30
	TTL_DAY     time.Duration = time.Hour * 24
	TTL_HOUR    time.Duration = time.Hour //time.Minute * 60
	TTL_20_MINS time.Duration = time.Minute * 20
	TTL_15_MINS time.Duration = time.Minute * 15
	TTL_10_MINS time.Duration = time.Minute * 10
)

const JWT_CLAIM_SEP = " "

type TokenClaims struct {
	jwt.RegisteredClaims
	PublicId string    `json:"publicId"`
	Type     TokenType `json:"type"`
	Data     string    `json:"data,omitempty"`
	Otp      string    `json:"otp,omitempty"`
	Scope    string    `json:"scope,omitempty"`
	//Roles    []string `json:"roles,omitempty"`
	Roles string `json:"roles,omitempty"`
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
	return strings.Join(claims, JWT_CLAIM_SEP)
}

type TokenGen struct {
	secret         *rsa.PrivateKey
	accessTokenTTL time.Duration
	otpTokenTTL    time.Duration
	shortTTL       time.Duration
}

func NewTokenGen(secret *rsa.PrivateKey) *TokenGen {
	return &TokenGen{secret: secret,
		accessTokenTTL: env.GetMin("ACCESS_TOKEN_TTL_MINS", TTL_15_MINS),
		otpTokenTTL:    env.GetMin("OTP_TOKEN_TTL_MINS", TTL_20_MINS),
		shortTTL:       env.GetMin("SHORT_TTL_MINS", TTL_10_MINS)}
}

func (tc *TokenGen) SetAccessTokenTTL(ttl time.Duration) *TokenGen {
	tc.accessTokenTTL = ttl
	return tc
}

func (tc *TokenGen) SetOTPTokenTTL(ttl time.Duration) *TokenGen {
	tc.otpTokenTTL = ttl
	return tc
}

func (tc *TokenGen) RefreshToken(c echo.Context, publicId string, roles string) (string, error) {
	return tc.BasicToken(c,
		publicId,
		REFRESH_TOKEN,

		TTL_HOUR)
}

func (tc *TokenGen) AccessToken(c echo.Context, publicId string, roles string) (string, error) {

	claims := TokenClaims{
		PublicId: publicId,
		//IpAddr:           ipAddr,
		Type:             ACCESS_TOKEN,
		Roles:            roles,
		RegisteredClaims: makeClaims(tc.accessTokenTTL)}

	return tc.BaseToken(claims)
}

func (tc *TokenGen) VerifyEmailToken(c echo.Context, publicId string) (string, error) {
	return tc.ShortTimeToken(c,
		publicId,
		VERIFY_EMAIL_TOKEN)
}

func (tc *TokenGen) ResetPasswordToken(c echo.Context, user *AuthUser) (string, error) {
	claims := TokenClaims{
		PublicId: user.PublicId,
		// include first name to personalize reset
		Data:             user.FirstName,
		Type:             RESET_PASSWORD_TOKEN,
		Otp:              CreateOTP(user),
		RegisteredClaims: makeClaims(tc.otpTokenTTL)}

	return tc.BaseToken(claims)
}

func (tc *TokenGen) ResetEmailToken(c echo.Context, user *AuthUser, email *mail.Address) (string, error) {

	claims := TokenClaims{
		PublicId:         user.PublicId,
		Data:             email.Address,
		Type:             CHANGE_EMAIL_TOKEN,
		Otp:              CreateOTP(user),
		RegisteredClaims: makeClaims(tc.otpTokenTTL)}

	return tc.BaseToken(claims)

}

func (tc *TokenGen) PasswordlessToken(c echo.Context, publicId string) (string, error) {
	return tc.ShortTimeToken(c,
		publicId,
		PASSWORDLESS_TOKEN)
}

func (tc *TokenGen) OTPToken(c echo.Context, user *AuthUser, tokenType TokenType) (string, error) {
	claims := TokenClaims{
		PublicId:         user.PublicId,
		Type:             tokenType,
		Otp:              CreateOTP(user),
		RegisteredClaims: makeClaims(tc.shortTTL),
	}

	return tc.BaseToken(claims)
}

// Generate short lived tokens for one time passcode use.
func (tc *TokenGen) ShortTimeToken(c echo.Context,
	publicId string,
	tokenType TokenType) (string, error) {
	return tc.BasicToken(c, publicId, tokenType, tc.shortTTL)
}

func (tc *TokenGen) BasicToken(c echo.Context,
	publicId string,
	tokenType TokenType,
	ttl time.Duration) (string, error) {
	claims := TokenClaims{
		PublicId:         publicId,
		Type:             tokenType,
		RegisteredClaims: makeClaims(ttl),
	}

	return tc.BaseToken(claims)
}

func (tc *TokenGen) BaseToken(claims jwt.Claims) (string, error) {

	// Create token with claims
	//token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Generate encoded token and send it as response.
	t, err := token.SignedString(tc.secret)

	if err != nil {
		return "", err
	}

	//log.Debug().Msgf("token %s", t)

	return t, nil
}

func makeClaims(ttl time.Duration) jwt.RegisteredClaims {
	return jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl))}
}

// Get the unique permissions associated with a user based
// on their jwt permissions
/* func RolesToPermissions(roleMap *RoleMap) []string {
	permissionSet := make(map[string]struct{})

	for role := range *roleMap {

		for _, permission := range (*roleMap)[role] {
			_, ok := permissionSet[permission]

			if !ok {
				permissionSet[permission] = struct{}{}
			}
		}
	}

	// sort
	ret := make([]string, 0, len(permissionSet))

	for permission := range permissionSet {
		ret = append(ret, permission)
	}

	sort.Strings(ret)

	return ret
} */
