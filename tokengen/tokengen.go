package tokengen

import (
	"crypto/rsa"
	"net/mail"
	"sync"

	"github.com/antonybholmes/go-auth"
	"github.com/gin-gonic/gin"
)

var tc *auth.TokenCreator
var once sync.Once

func Init(secret *rsa.PrivateKey) {
	once.Do(func() {
		tc = auth.NewTokenCreator(secret)
	})
}

func RefreshToken(c *gin.Context, user *auth.AuthUser) (string, error) {
	return tc.RefreshToken(c, user)
}

func AccessToken(c *gin.Context, publicId string, roles string) (string, error) {
	return tc.AccessToken(c, publicId, roles)
}

func VerifyEmailToken(c *gin.Context, authUser *auth.AuthUser, visitUrl string) (string, error) {
	return tc.VerifyEmailToken(c, authUser, visitUrl)
}

func ResetPasswordToken(c *gin.Context, user *auth.AuthUser) (string, error) {
	return tc.ResetPasswordToken(c, user)
}

func ResetEmailToken(c *gin.Context, user *auth.AuthUser, email *mail.Address) (string, error) {
	return tc.ResetEmailToken(c, user, email)
}

func PasswordlessToken(c *gin.Context, publicId string, visitUrl string) (string, error) {
	return tc.PasswordlessToken(c, publicId, visitUrl)
}

func OneTimeToken(c *gin.Context, user *auth.AuthUser, tokenType auth.TokenType) (string, error) {
	return tc.OTPToken(c, user, tokenType)
}
