package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

type TokenType = uint8

const (
	TOKEN_TYPE_VERIFY_EMAIL TokenType = iota
	TOKEN_TYPE_PASSWORDLESS
	TOKEN_TYPE_RESET_PASSWORD
	TOKEN_TYPE_REFRESH
	TOKEN_TYPE_ACCESS
)

const TOKEN_TYPE_OTP string = "otp"

const TOKEN_TYPE_REFRESH_TTL_HOURS time.Duration = time.Hour * 24
const TOKEN_TYPE_ACCESS_TTL_MINS time.Duration = time.Minute * 60
const TOKEN_TYPE_OTP_TTL_MINS time.Duration = time.Minute * 10

type JwtCustomClaims struct {
	Uuid string `json:"uuid"`
	//Name  string `json:"name"`
	Type TokenType `json:"type"`
	//IpAddr string    `json:"ipAddr"`
	jwt.RegisteredClaims
}

// type JwtOtpCustomClaims struct {
// 	OTP string `json:"otp"`
// 	JwtCustomClaims
// }

func TokenTypeString(t TokenType) string {
	switch t {
	case TOKEN_TYPE_VERIFY_EMAIL:
		return "verify_email_token"
	case TOKEN_TYPE_PASSWORDLESS:
		return "passwordless_token"
	case TOKEN_TYPE_RESET_PASSWORD:
		return "reset_password_token"
	case TOKEN_TYPE_ACCESS:
		return "access_token"
	case TOKEN_TYPE_REFRESH:
		return "refresh_token"
	default:
		return "other"
	}
}

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
		jwt.NewNumericDate(time.Now().Add(TOKEN_TYPE_ACCESS_TTL_MINS)))
}

func VerifyEmailToken(c echo.Context, uuid string, secret string) (string, error) {
	return OtpToken(c,
		uuid,
		TOKEN_TYPE_VERIFY_EMAIL,
		secret)
}

func ResetPasswordToken(c echo.Context, uuid string, secret string) (string, error) {
	return OtpToken(c,
		uuid,
		TOKEN_TYPE_RESET_PASSWORD,
		secret)
}

func PasswordlessToken(c echo.Context, uuid string, secret string) (string, error) {
	return OtpToken(c,
		uuid,
		TOKEN_TYPE_PASSWORDLESS,
		secret)
}

func OtpToken(c echo.Context, uuid string, tokenType TokenType, secret string) (string, error) {
	return JwtToken(c, uuid,
		tokenType,
		secret,
		jwt.NewNumericDate(time.Now().Add(TOKEN_TYPE_OTP_TTL_MINS)))
}

func JwtToken(c echo.Context, uuid string, tokenType TokenType, secret string, expires *jwt.NumericDate) (string, error) {

	claims := JwtCustomClaims{
		Uuid: uuid,
		//IpAddr:           ipAddr,
		Type:             tokenType,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: expires},
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate encoded token and send it as response.
	t, err := token.SignedString([]byte(secret))

	if err != nil {
		return "", err
	}

	return t, nil
}
