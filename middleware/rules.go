package middleware

import (
	"github.com/antonybholmes/go-web"
	"github.com/antonybholmes/go-web/access"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func RulesMiddleware(claimsParser JWTClaimsFunc, ruleEngine *access.RuleEngine) gin.HandlerFunc {
	// create a function that extracts user from context
	parseFunc := ParseUserJWT(claimsParser)

	return func(c *gin.Context) {
		// extract user from context
		user, err := parseFunc(c)

		if err != nil {
			c.Error(err)
			c.Abort()
			return
		}

		// use pointer to token
		c.Set("user", &user)

		log.Debug().Msgf("Checking access for method=%s, path=%s, tokenType=%s, roles=%v", c.Request.Method, c.FullPath(), user.Type, user.Roles)

		err = ruleEngine.IsAccessAllowed(c.Request.Method, c.FullPath(), user.Type, user.Roles)

		if err != nil {
			log.Debug().Msgf("Access denied: %v", err)
			web.ForbiddenResp(c, err)
			return
		}

		c.Next()

	}
}
