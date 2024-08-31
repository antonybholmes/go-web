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

func RefreshJwt(c echo.Context, publicId string, roles string) (string, error) {
	return tc.RefreshJwt(c, publicId, roles)
}

func AccessJwt(c echo.Context, publicId string, roles string) (string, error) {
	return tc.AccessJwt(c, publicId, roles)
}

func VerifyEmailJwt(c echo.Context, publicId string) (string, error) {
	return tc.VerifyEmailJwt(c, publicId)
}

func ResetPasswordJwt(c echo.Context, user *auth.AuthUser) (string, error) {
	return tc.ResetPasswordJwt(c, user)
}

func ResetEmailJwt(c echo.Context, user *auth.AuthUser, email *mail.Address) (string, error) {
	return tc.ResetEmailJwt(c, user, email)
}

func PasswordlessJwt(c echo.Context, publicId string) (string, error) {
	return tc.PasswordlessJwt(c, publicId)
}

func OneTimeJwt(c echo.Context, user *auth.AuthUser, tokenType auth.JwtType) (string, error) {
	return tc.OneTimeJwt(c, user, tokenType)
}
