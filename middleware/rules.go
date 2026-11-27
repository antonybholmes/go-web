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
func AccessTokenRulesMiddleware(userClaimsParser *UserJWTParser, ruleEngine *access.RuleEngine) gin.HandlerFunc {
	// create a function that extracts user from context

	return func(c *gin.Context) {
		// extract userToken from context
		userToken, err := userClaimsParser.Parse(c)

		if err != nil {
			web.UnauthorizedResp(c, err)
			return
		}

		// check it is an access token
		if userToken.Type != token.TokenTypeAccess {
			web.ForbiddenResp(c, fmt.Errorf("invalid token type"))
			return
		}

		//log.Debug().Msgf("Checking access for method=%s, path=%s, tokenType=%s, roles=%v", c.Request.Method, c.FullPath(), userToken.Type, userToken.Roles)

		// Use the route engine to check access based on the path, user token type and the permissions in the token
		err = ruleEngine.IsAccessAllowed(access.MethodType(c.Request.Method),
			c.FullPath(),
			userToken)

		if err != nil {
			log.Debug().Msgf("access denied: %v", err)
			web.ForbiddenResp(c, err)
			return
		}

		// use pointer to token
		c.Set("user", userToken)

		c.Next()

	}
}
