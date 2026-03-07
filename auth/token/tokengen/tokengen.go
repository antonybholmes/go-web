package tokengen

import (
	"net/mail"
	"sync"

	"github.com/antonybholmes/go-web/auth"
	"github.com/antonybholmes/go-web/auth/token"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
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

func RefreshToken(c *gin.Context, user *auth.AuthUser, audience jwt.ClaimStrings) (string, error) {
	return tc.RefreshToken(c, user, audience)
}

func AccessToken(c *gin.Context,
	userId string,
	audience jwt.ClaimStrings,
	roles []*auth.Role) (string, error) {
	return tc.AccessToken(c, userId, audience, roles)
}

func AccessTokenUsingPermissions(c *gin.Context,
	userId string,
	audience jwt.ClaimStrings,
	permissions []string) (string, error) {
	return tc.AccessTokenUsingPermissions(c, userId, audience, permissions)
}

func UpdateToken(c *gin.Context, userId string, audience jwt.ClaimStrings, roles []*auth.Role) (string, error) {
	return tc.UpdateToken(c, userId, audience, roles)
}

func MakeVerifyEmailToken(c *gin.Context, authUser *auth.AuthUser, audience jwt.ClaimStrings, visitUrl string) (string, error) {
	return tc.MakeVerifyEmailToken(c, authUser, audience, visitUrl)
}

func MakeResetPasswordToken(c *gin.Context, user *auth.AuthUser, audience jwt.ClaimStrings) (string, error) {
	return tc.MakeResetPasswordToken(c, user, audience)
}

func MakeResetEmailToken(c *gin.Context, user *auth.AuthUser, audience jwt.ClaimStrings, email *mail.Address) (string, error) {
	return tc.MakeResetEmailToken(c, user, audience, email)
}

func MakePasswordlessToken(c *gin.Context, userId string, audience jwt.ClaimStrings, url string) (string, error) {
	return tc.MakePasswordlessToken(c, userId, audience, url)
}

func OneTimeToken(c *gin.Context, user *auth.AuthUser, audience jwt.ClaimStrings, tokenType string) (string, error) {
	return tc.OTPToken(c, user, audience, tokenType)
}
