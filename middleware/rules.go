package middleware

import (
	"fmt"

	"github.com/antonybholmes/go-sys/log"
	"github.com/antonybholmes/go-web"
	"github.com/antonybholmes/go-web/access"
	"github.com/antonybholmes/go-web/auth/token"
	"github.com/gin-gonic/gin"
)

// AccessTokenRulesMiddleware checks if the user has access based on the access token
// and the rules defined in the rule engine.
func AccessTokenRulesMiddleware(claimsParser *UserJWTParser, ruleEngine *access.RuleEngine) gin.HandlerFunc {
	// create a function that extracts user from context

	return func(c *gin.Context) {
		// extract userToken from context
		userToken, err := claimsParser.Parse(c)

		if err != nil {
			c.Error(err)
			c.Abort()
			return
		}

		// check it is an access token
		if userToken.Type != token.TokenTypeAccess {
			web.ForbiddenResp(c, fmt.Errorf("invalid token type"))
			c.Abort()
			return
		}

		// use pointer to token
		c.Set("user", userToken)

		//log.Debug().Msgf("Checking access for method=%s, path=%s, tokenType=%s, roles=%v", c.Request.Method, c.FullPath(), userToken.Type, userToken.Roles)

		// Use the route engine to check access based on the path, user token type and the permissions in the token
		err = ruleEngine.IsAccessAllowed(c.Request.Method,
			c.FullPath(),
			userToken)

		if err != nil {
			log.Debug().Msgf("access denied: %v", err)
			web.ForbiddenResp(c, err)
			return
		}

		c.Next()

	}
}
