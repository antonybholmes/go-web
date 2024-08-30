package auth

import (
	"crypto/rsa"
	"net/mail"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

type TokenType = uint

const (
	TOKEN_TYPE_VERIFY_EMAIL   TokenType = 1
	TOKEN_TYPE_PASSWORDLESS   TokenType = 2
	TOKEN_TYPE_RESET_PASSWORD TokenType = 3
	TOKEN_TYPE_CHANGE_EMAIL   TokenType = 4
	TOKEN_TYPE_REFRESH        TokenType = 5
	TOKEN_TYPE_ACCESS         TokenType = 6
	TOKEN_TYPE_OTP            TokenType = 7
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
	TOKEN_TTL_YEAR    time.Duration = time.Hour * 24 * 365
	TOKEN_TTL_30_DAYS time.Duration = time.Hour * 24 * 30
	TOKEN_TTL_DAY     time.Duration = time.Hour * 24
	TOKEN_TTL_HOUR    time.Duration = time.Hour //time.Minute * 60
	TOKEN_TTL_20_MINS time.Duration = time.Minute * 20
	TOKEN_TTL_10_MINS time.Duration = time.Minute * 10
)

const JWT_CLAIM_SEP = " "

type JwtCustomClaims struct {
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

type JwtGen struct {
	secret *rsa.PrivateKey
}

func NewJwtGen(secret *rsa.PrivateKey) *JwtGen {
	return &JwtGen{secret: secret}
}

func (tc *JwtGen) RefreshToken(c echo.Context, publicId string, roles string) (string, error) {
	return tc.BaseAuthToken(c,
		publicId,
		TOKEN_TYPE_REFRESH,
		roles)
}

func (tc *JwtGen) AccessToken(c echo.Context, publicId string, roles string) (string, error) {
	return tc.BaseAuthToken(c,
		publicId,
		TOKEN_TYPE_ACCESS,
		roles)
}

// token for all possible values
func (tc *JwtGen) BaseAuthToken(c echo.Context,
	publicId string,
	tokenType TokenType,
	roles string) (string, error) {

	claims := JwtCustomClaims{
		PublicId: publicId,
		//IpAddr:           ipAddr,
		Type:             tokenType,
		Roles:            roles,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(TOKEN_TTL_HOUR))},
	}

	return tc.BaseJwtToken(claims)
}

func (tc *JwtGen) VerifyEmailToken(c echo.Context, publicId string) (string, error) {
	return tc.ShortTimeToken(c,
		publicId,
		TOKEN_TYPE_VERIFY_EMAIL)
}

func (tc *JwtGen) ResetPasswordToken(c echo.Context, user *AuthUser) (string, error) {

	claims := JwtCustomClaims{
		PublicId: user.PublicId,
		// include first name to personalize reset
		Data:             user.FirstName,
		Type:             TOKEN_TYPE_RESET_PASSWORD,
		Otp:              CreateOTP(user),
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(TOKEN_TTL_10_MINS))}}

	return tc.BaseJwtToken(claims)
}

func (tc *JwtGen) ChangeEmailToken(c echo.Context, user *AuthUser, email *mail.Address) (string, error) {

	claims := JwtCustomClaims{
		PublicId:         user.PublicId,
		Data:             email.Address,
		Type:             TOKEN_TYPE_CHANGE_EMAIL,
		Otp:              CreateOTP(user),
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(TOKEN_TTL_20_MINS))}}

	return tc.BaseJwtToken(claims)

}

func (tc *JwtGen) PasswordlessToken(c echo.Context, publicId string) (string, error) {
	return tc.ShortTimeToken(c,
		publicId,
		TOKEN_TYPE_PASSWORDLESS)
}

func (tc *JwtGen) OneTimeToken(c echo.Context, user *AuthUser, tokenType TokenType) (string, error) {
	claims := JwtCustomClaims{
		PublicId:         user.PublicId,
		Type:             tokenType,
		Otp:              CreateOTP(user),
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(TOKEN_TTL_10_MINS))},
	}

	return tc.BaseJwtToken(claims)
}

// Generate short lived tokens for one time passcode use.
func (tc *JwtGen) ShortTimeToken(c echo.Context, publicId string, tokenType TokenType) (string, error) {
	claims := JwtCustomClaims{
		PublicId:         publicId,
		Type:             tokenType,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(TOKEN_TTL_10_MINS))},
	}

	return tc.BaseJwtToken(claims)
}

func (tc *JwtGen) BaseJwtToken(claims jwt.Claims) (string, error) {

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
