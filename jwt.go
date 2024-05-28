package auth

import (
	"crypto/rsa"
	"net/mail"
	"sort"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// type TokenType = uint8

// const (
// 	TOKEN_TYPE_VERIFY_EMAIL TokenType = iota
// 	TOKEN_TYPE_PASSWORDLESS
// 	TOKEN_TYPE_RESET_PASSWORD
// 	TOKEN_TYPE_REFRESH
// 	TOKEN_TYPE_ACCESS
// )

type TokenType = string

const (
	TOKEN_TYPE_VERIFY_EMAIL   TokenType = "verify_email"
	TOKEN_TYPE_PASSWORDLESS   TokenType = "passwordless"
	TOKEN_TYPE_RESET_PASSWORD TokenType = "reset_password"
	TOKEN_TYPE_CHANGE_EMAIL   TokenType = "change_email"
	TOKEN_TYPE_REFRESH        TokenType = "refresh"
	TOKEN_TYPE_ACCESS         TokenType = "access"
)

const TOKEN_TYPE_OTP string = "otp"

const TOKEN_TYPE_REFRESH_TTL_HOURS time.Duration = time.Hour * 24
const TOKEN_TYPE_ACCESS_TTL_HOURS time.Duration = time.Hour //time.Minute * 60
const TOKEN_TYPE_SHORT_TIME_TTL_MINS time.Duration = time.Minute * 10

type JwtCustomClaims struct {
	Uuid  string  `json:"uuid"`
	Type  string  `json:"type"`
	Data  string  `json:"data,omitempty"`
	Otp   string  `json:"otp,omitempty"`
	Roles RoleMap `json:"roles,omitempty"`
	//Permissions string `json:"permissions,omitempty"`
	//IpAddr string    `json:"ipAddr"`
	jwt.RegisteredClaims
}

type RoleMap map[string][]string

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

func RefreshToken(c echo.Context, uuid string, roles *RoleMap, secret *rsa.PrivateKey) (string, error) {
	return BaseAuthToken(c,
		uuid,
		TOKEN_TYPE_REFRESH,
		roles,

		secret)
}

func AccessToken(c echo.Context, uuid string, roles *RoleMap, secret *rsa.PrivateKey) (string, error) {
	return BaseAuthToken(c,
		uuid,
		TOKEN_TYPE_ACCESS,
		roles,

		secret)
}

// token for all possible values
func BaseAuthToken(c echo.Context,
	uuid string,
	tokenType TokenType,
	roles *RoleMap,

	secret *rsa.PrivateKey) (string, error) {

	claims := JwtCustomClaims{
		Uuid: uuid,
		//IpAddr:           ipAddr,
		Type:  tokenType,
		Roles: *roles,

		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(TOKEN_TYPE_ACCESS_TTL_HOURS))},
	}

	return BaseJwtToken(claims, secret)
}

func VerifyEmailToken(c echo.Context, uuid string, secret *rsa.PrivateKey) (string, error) {
	return ShortTimeToken(c,
		uuid,
		TOKEN_TYPE_VERIFY_EMAIL,
		secret)
}

func ResetPasswordToken(c echo.Context, user *AuthUser, secret *rsa.PrivateKey) (string, error) {

	claims := JwtCustomClaims{
		Uuid:             user.Uuid,
		Data:             user.Username,
		Type:             TOKEN_TYPE_RESET_PASSWORD,
		Otp:              CreateOtp(user),
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(TOKEN_TYPE_SHORT_TIME_TTL_MINS))}}

	return BaseJwtToken(claims, secret)

}

func ChangeEmailToken(c echo.Context, user *AuthUser, email *mail.Address, secret *rsa.PrivateKey) (string, error) {

	claims := JwtCustomClaims{
		Uuid:             user.Uuid,
		Data:             email.Address,
		Type:             TOKEN_TYPE_CHANGE_EMAIL,
		Otp:              CreateOtp(user),
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(TOKEN_TYPE_SHORT_TIME_TTL_MINS))}}

	return BaseJwtToken(claims, secret)

}

func PasswordlessToken(c echo.Context, uuid string, secret *rsa.PrivateKey) (string, error) {
	return ShortTimeToken(c,
		uuid,
		TOKEN_TYPE_PASSWORDLESS,
		secret)
}

func OneTimeToken(c echo.Context, user *AuthUser, tokenType TokenType, secret *rsa.PrivateKey) (string, error) {
	claims := JwtCustomClaims{
		Uuid:             user.Uuid,
		Type:             tokenType,
		Otp:              CreateOtp(user),
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(TOKEN_TYPE_SHORT_TIME_TTL_MINS))},
	}

	return BaseJwtToken(claims, secret)
}

// Generate short lived tokens for one time passcode use.
func ShortTimeToken(c echo.Context, uuid string, tokenType TokenType, secret *rsa.PrivateKey) (string, error) {
	claims := JwtCustomClaims{
		Uuid:             uuid,
		Type:             tokenType,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(TOKEN_TYPE_SHORT_TIME_TTL_MINS))},
	}

	return BaseJwtToken(claims, secret)
}

// simple non otp token
// func JwtToken(c echo.Context,
// 	uuid string,
// 	tokenType TokenType,
// 	permissions string,
// 	secret *rsa.PrivateKey,
// 	expires *jwt.NumericDate) (string, error) {
// 	return BasicJwtToken(c, uuid, tokenType, permissions, "", secret, expires)
// }

func BaseJwtToken(claims jwt.Claims, secret *rsa.PrivateKey) (string, error) {

	// Create token with claims
	//token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Generate encoded token and send it as response.
	t, err := token.SignedString(secret)

	if err != nil {
		return "", err
	}

	return t, nil
}

// Get the unique permissions associated with a user based
// on their jwt roles
func RolesToPermissions(roles *RoleMap) []string {
	permissionSet := make(map[string]struct{})

	for role := range *roles {

		for _, permission := range (*roles)[role] {
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
}
