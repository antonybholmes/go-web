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
	Uuid string `json:"uuid"`
	Data string `json:"data"`
	Type string `json:"type"`
	Otp  string `json:"otp"`
	//IpAddr string    `json:"ipAddr"`
	jwt.RegisteredClaims
}

type JwtResetPasswordClaims struct {
	Username string `json:"username"`
	JwtCustomClaims
}

type JwtUpdateEmailClaims struct {
	Email string `json:"email"`
	JwtCustomClaims
}

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

func RefreshToken(c echo.Context, uuid string, secret string) (string, error) {
	return JwtToken(c,
		uuid,
		TOKEN_TYPE_REFRESH,
		secret,
		jwt.NewNumericDate(time.Now().Add(TOKEN_TYPE_REFRESH_TTL_HOURS)))
}

func AccessToken(c echo.Context, uuid string, secret string) (string, error) {
	return JwtToken(c,
		uuid,
		TOKEN_TYPE_ACCESS,
		secret,
		jwt.NewNumericDate(time.Now().Add(TOKEN_TYPE_ACCESS_TTL_HOURS)))
}

func VerifyEmailToken(c echo.Context, uuid string, secret string) (string, error) {
	return ShortTimeToken(c,
		uuid,
		TOKEN_TYPE_VERIFY_EMAIL,
		secret)
}

func ResetPasswordToken(c echo.Context, user *AuthUser, secret string) (string, error) {

	claims := JwtResetPasswordClaims{

		JwtCustomClaims: JwtCustomClaims{
			Uuid:             user.Uuid,
			Type:             TOKEN_TYPE_RESET_PASSWORD,
			Otp:              CreateOtp(user),
			RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(TOKEN_TYPE_SHORT_TIME_TTL_MINS))}},
		Username: user.Username}

	return BaseJwtToken(c, claims, secret)

}

func ChangeEmailToken(c echo.Context, user *AuthUser, email *mail.Address, secret string) (string, error) {

	claims := JwtCustomClaims{
		Uuid:             user.Uuid,
		Data:             email.Address,
		Type:             TOKEN_TYPE_RESET_PASSWORD,
		Otp:              CreateOtp(user),
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(TOKEN_TYPE_SHORT_TIME_TTL_MINS))}}

	return BaseJwtToken(c, claims, secret)

}

func PasswordlessToken(c echo.Context, uuid string, secret string) (string, error) {
	return ShortTimeToken(c,
		uuid,
		TOKEN_TYPE_PASSWORDLESS,
		secret)
}

func OneTimeToken(c echo.Context, user *AuthUser, tokenType TokenType, secret string) (string, error) {
	return BasicJwtToken(c, user.Uuid,
		tokenType,
		CreateOtp(user),
		secret,
		jwt.NewNumericDate(time.Now().Add(TOKEN_TYPE_SHORT_TIME_TTL_MINS)))
}

// Generate short lived tokens for one time passcode use.
func ShortTimeToken(c echo.Context, uuid string, tokenType TokenType, secret string) (string, error) {
	return JwtToken(c, uuid,
		tokenType,
		secret,
		jwt.NewNumericDate(time.Now().Add(TOKEN_TYPE_SHORT_TIME_TTL_MINS)))
}

// simple non otp token
func JwtToken(c echo.Context, uuid string, tokenType TokenType, secret string, expires *jwt.NumericDate) (string, error) {
	return BasicJwtToken(c, uuid, tokenType, "", secret, expires)
}

// token for all possible values
func BasicJwtToken(c echo.Context, uuid string, tokenType TokenType, otp string, secret string, expires *jwt.NumericDate) (string, error) {

	claims := JwtCustomClaims{
		Uuid: uuid,
		//IpAddr:           ipAddr,
		Type:             tokenType,
		Otp:              otp,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: expires},
	}

	return BaseJwtToken(c, claims, secret)
}

func BaseJwtToken(c echo.Context, claims jwt.Claims, secret string) (string, error) {

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate encoded token and send it as response.
	t, err := token.SignedString([]byte(secret))

	if err != nil {
		return "", err
	}

	return t, nil
}
