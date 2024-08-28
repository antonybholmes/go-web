package jwtgen

import (
	"crypto/rsa"
	"net/mail"
	"sync"

	"github.com/antonybholmes/go-auth"
	"github.com/labstack/echo/v4"
)

var tc *auth.JwtGen
var once sync.Once

func Init(secret *rsa.PrivateKey) {
	once.Do(func() {
		tc = auth.NewJwtGen(secret)
	})
}

func RefreshToken(c echo.Context, publicId string, roles string) (string, error) {
	return tc.RefreshToken(c, publicId, roles)
}

func AccessToken(c echo.Context, publicId string, roles string) (string, error) {
	return tc.AccessToken(c, publicId, roles)
}

func VerifyEmailToken(c echo.Context, publicId string) (string, error) {
	return tc.VerifyEmailToken(c, publicId)
}

func ResetPasswordToken(c echo.Context, user *auth.AuthUser) (string, error) {
	return tc.ResetPasswordToken(c, user)
}

func ResetEmailToken(c echo.Context, user *auth.AuthUser, email *mail.Address) (string, error) {
	return tc.ChangeEmailToken(c, user, email)
}

func PasswordlessToken(c echo.Context, publicId string) (string, error) {
	return tc.PasswordlessToken(c, publicId)
}

func OneTimeToken(c echo.Context, user *auth.AuthUser, tokenType auth.TokenType) (string, error) {
	return tc.OneTimeToken(c, user, tokenType)
}
