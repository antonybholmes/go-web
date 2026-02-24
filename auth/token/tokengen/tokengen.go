package tokengen

import (
	"net/mail"
	"sync"

	"github.com/antonybholmes/go-web/auth"
	"github.com/antonybholmes/go-web/auth/token"
	"github.com/gin-gonic/gin"
)

var (
	tc   *token.TokenCreator
	once sync.Once
)

func Init(tokenSigner token.TokenSigner) {
	once.Do(func() {
		tc = token.NewTokenCreator(tokenSigner)
	})
}

func RefreshToken(c *gin.Context, user *auth.AuthUser) (string, error) {
	return tc.RefreshToken(c, user)
}

func AccessToken(c *gin.Context, publicId string, roles []*auth.Role) (string, error) {
	return tc.AccessToken(c, publicId, roles)
}

func AccessTokenUsingPermissions(c *gin.Context, publicId string, permissions []string) (string, error) {
	return tc.AccessTokenUsingPermissions(c, publicId, permissions)
}

func UpdateToken(c *gin.Context, publicId string, roles []*auth.Role) (string, error) {
	return tc.UpdateToken(c, publicId, roles)
}

func MakeVerifyEmailToken(c *gin.Context, authUser *auth.AuthUser, visitUrl string) (string, error) {
	return tc.MakeVerifyEmailToken(c, authUser, visitUrl)
}

func MakeResetPasswordToken(c *gin.Context, user *auth.AuthUser) (string, error) {
	return tc.MakeResetPasswordToken(c, user)
}

func MakeResetEmailToken(c *gin.Context, user *auth.AuthUser, email *mail.Address) (string, error) {
	return tc.MakeResetEmailToken(c, user, email)
}

func MakePasswordlessToken(c *gin.Context, userId string, url string) (string, error) {
	return tc.MakePasswordlessToken(c, userId, url)
}

func OneTimeToken(c *gin.Context, user *auth.AuthUser, tokenType string) (string, error) {
	return tc.OTPToken(c, user, tokenType)
}
