package oauth2

import (
	"fmt"

	"github.com/antonybholmes/go-web"
	"github.com/antonybholmes/go-web/auth"
	"github.com/antonybholmes/go-web/auth/oauth2"
	"github.com/antonybholmes/go-web/middleware"
	"github.com/gin-gonic/gin"
)

// OpenID Connect JWT Middleware
func JwtOIDCMiddleware(verifier *oauth2.OIDCVerifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := middleware.ParseToken(c)

		if err != nil {
			web.UnauthorizedResp(c, auth.NewTokenError(fmt.Sprintf("token is not valid: %s", err.Error())))
			return
		}

		// Verify the token
		claims, err := verifier.Verify(tokenString)

		if err != nil {
			web.UnauthorizedResp(c, auth.NewTokenError(fmt.Sprintf("could not verify token, %s", err.Error())))
			return
		}

		// Store claims in context for downstream handlers
		c.Set("user", claims)
		c.Next()
	}
}
