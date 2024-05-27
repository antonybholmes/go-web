package auth

import (
	"net/mail"
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
	Uuid  string `json:"uuid"`
	Type  string `json:"type"`
	Data  string `json:"data,omitempty"`
	Otp   string `json:"otp,omitempty"`
	Scope string `json:"scope,omitempty"`
	//IpAddr string    `json:"ipAddr"`
	jwt.RegisteredClaims
}

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

func RefreshToken(c echo.Context, uuid string, scope string, secret []byte) (string, error) {
	return JwtToken(c,
		uuid,
		TOKEN_TYPE_REFRESH,
		scope,
		secret,
		jwt.NewNumericDate(time.Now().Add(TOKEN_TYPE_REFRESH_TTL_HOURS)))
}

func AccessToken(c echo.Context, uuid string, scope string, secret []byte) (string, error) {
	return JwtToken(c,
		uuid,
		TOKEN_TYPE_ACCESS,
		scope,
		secret,
		jwt.NewNumericDate(time.Now().Add(TOKEN_TYPE_ACCESS_TTL_HOURS)))
}

func VerifyEmailToken(c echo.Context, uuid string, secret []byte) (string, error) {
	return ShortTimeToken(c,
		uuid,
		TOKEN_TYPE_VERIFY_EMAIL,
		secret)
}

func ResetPasswordToken(c echo.Context, user *AuthUser, secret []byte) (string, error) {

	claims := JwtCustomClaims{
		Uuid:             user.Uuid,
		Data:             user.Username,
		Type:             TOKEN_TYPE_RESET_PASSWORD,
		Otp:              CreateOtp(user),
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(TOKEN_TYPE_SHORT_TIME_TTL_MINS))}}

	return BaseJwtToken(c, claims, secret)

}

func ChangeEmailToken(c echo.Context, user *AuthUser, email *mail.Address, secret []byte) (string, error) {

	claims := JwtCustomClaims{
		Uuid:             user.Uuid,
		Data:             email.Address,
		Type:             TOKEN_TYPE_CHANGE_EMAIL,
		Otp:              CreateOtp(user),
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(TOKEN_TYPE_SHORT_TIME_TTL_MINS))}}

	return BaseJwtToken(c, claims, secret)

}

func PasswordlessToken(c echo.Context, uuid string, secret []byte) (string, error) {
	return ShortTimeToken(c,
		uuid,
		TOKEN_TYPE_PASSWORDLESS,
		secret)
}

func OneTimeToken(c echo.Context, user *AuthUser, tokenType TokenType, secret []byte) (string, error) {
	return BasicJwtToken(c, user.Uuid,
		tokenType,
		"",
		CreateOtp(user),
		secret,
		jwt.NewNumericDate(time.Now().Add(TOKEN_TYPE_SHORT_TIME_TTL_MINS)))
}

// Generate short lived tokens for one time passcode use.
func ShortTimeToken(c echo.Context, uuid string, tokenType TokenType, secret []byte) (string, error) {
	return JwtToken(c, uuid,
		tokenType,
		"",
		secret,
		jwt.NewNumericDate(time.Now().Add(TOKEN_TYPE_SHORT_TIME_TTL_MINS)))
}

// simple non otp token
func JwtToken(c echo.Context,
	uuid string,
	tokenType TokenType,
	scope string,
	secret []byte,
	expires *jwt.NumericDate) (string, error) {
	return BasicJwtToken(c, uuid, tokenType, scope, "", secret, expires)
}

// token for all possible values
func BasicJwtToken(c echo.Context,
	uuid string,
	tokenType TokenType,
	scope string,
	otp string,
	secret []byte,
	expires *jwt.NumericDate) (string, error) {

	claims := JwtCustomClaims{
		Uuid: uuid,
		//IpAddr:           ipAddr,
		Type:             tokenType,
		Scope:            scope,
		Otp:              otp,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: expires},
	}

	return BaseJwtToken(c, claims, secret)
}

func BaseJwtToken(c echo.Context, claims jwt.Claims, secret []byte) (string, error) {

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
