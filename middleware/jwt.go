package middleware

import (
	"errors"
	"fmt"

	"github.com/antonybholmes/go-web"
	"github.com/antonybholmes/go-web/auth"
	"github.com/antonybholmes/go-web/auth/token"
	"github.com/gin-gonic/gin"
)

// Uses the a generic claims parser to parse the JWT
// stored in the bearer header specifically for AuthUserJwtClaims
func NewUserJWTParser(claimsParser JwtClaimsParser) *UserJWTParser {
	return &UserJWTParser{claimsParser: claimsParser}
}

// Get the user claims from the bearer token in the request header.
func (p *UserJWTParser) Parse(c *gin.Context) (*token.AuthUserJwtClaims, error) {
	tokenString, err := token.ParseToken(c)

	if err != nil {
		return nil, err
	}

	claims := token.AuthUserJwtClaims{}

	err = p.claimsParser.Parse(tokenString, &claims)

	if err != nil {
		return nil, err
	}

	return &claims, nil
}

// Handler for running directly as middleware
func (p *UserJWTParser) Handler(c *gin.Context) {
	claims, err := p.Parse(c)

	if err != nil {
		web.UserDoesNotExistResp(c)
		return
	}

	// use pointer to token
	c.Set("user", claims)

	// Continue processing the request
	c.Next()
}

// // Reads the token and parses the authorization JWT. If no jwt is present, aborts access.
// // If jwt is present it is added to the context as "user", thus subsequent handlers can
// // access it.
func UserJWTMiddleware(claimsParser *UserJWTParser) gin.HandlerFunc {

	return func(c *gin.Context) {

		claims, err := claimsParser.Parse(c)

		if err != nil {
			c.Error(err)
			c.Abort()
			return
		}

		// use pointer to token
		c.Set("user", claims)

		// Continue processing the request
		c.Next()
	}
}

// checks that user exists in context and calls f with the claims
// if it does which can be used to further validate it
func checkJWTUserExistsMiddleware(c *gin.Context, f func(c *gin.Context, claims *token.AuthUserJwtClaims)) {

	// user is a jwt
	user, err := GetJwtUser(c)

	if err != nil {
		web.UserDoesNotExistResp(c)
		return
	}

	f(c, user)
}

func JWTIsSpecificTokenTypeMiddleware(tokenType token.TokenType,
	userClaimsParser *UserJWTParser) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := userClaimsParser.Parse(c)

		if err != nil {
			web.UserDoesNotExistResp(c)
			return
		}

		if claims.Type != tokenType {
			web.ForbiddenResp(c, fmt.Errorf("wrong token type: %s, should be %s", claims.Type, tokenType))
			return
		}

		// use pointer to token
		c.Set("user", claims)

		// Continue processing the request
		c.Next()
	}

}

// func JWTIsSpecificTypeMiddleware(tokenType string) gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		log.Debug().Msgf("Handler: %s", c.FullPath())

// 		checkJWTUserExistsMiddleware(c, func(c *gin.Context, claims *token.AuthUserJwtClaims) {

// 			if claims.Type != tokenType {
// 				web.ForbiddenResp(c, fmt.Errorf("wrong token type: %s, should be %s", claims.Type, tokenType))

// 				return
// 			}

// 			c.Next()
// 		})
// 	}
// }

// func JwtIsRefreshTokenMiddleware() gin.HandlerFunc {
// 	return JWTIsSpecificTypeMiddleware(token.TokenTypeRefresh)
// }

// // make sure the supplied token is an access token
// func JwtIsAccessTokenMiddleware() gin.HandlerFunc {
// 	return JWTIsSpecificTypeMiddleware(token.TokenTypeAccess)
// }

// func JwtIsUpdateTokenMiddleware() gin.HandlerFunc {
// 	return JWTIsSpecificTypeMiddleware(token.TokenTypeUpdate)
// }

// func JwtIsVerifyEmailTokenMiddleware() gin.HandlerFunc {
// 	return JWTIsSpecificTypeMiddleware(token.TokenTypeVerifyEmail)
// }

func JwtIsAdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		checkJWTUserExistsMiddleware(c, func(c *gin.Context, claims *token.AuthUserJwtClaims) {

			// if !auth.HasAdminRole(claims.Roles) {
			// 	web.ForbiddenResp(c, auth.ErrUserIsNotAdmin)

			// 	return
			// }

			if !auth.HasAdminPermission(claims.Permissions) {
				web.ForbiddenResp(c, auth.ErrUserIsNotAdmin)

				return
			}

			c.Next()
		})
	}
}

func JwtCanSigninMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		checkJWTUserExistsMiddleware(c, func(c *gin.Context, claims *token.AuthUserJwtClaims) {

			// if !auth.HasWebLoginInRole(claims.Roles) {
			// 	web.ForbiddenResp(c, auth.ErrUserCannotLogin)
			// 	return
			// }

			if !auth.HasWebLoginPermission(claims.Permissions) {
				web.ForbiddenResp(c, auth.ErrUserCannotLogin)
				return
			}

			c.Next()
		})
	}
}

// func CSRFMiddleware() gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodOptions {
// 			c.Next()
// 			return
// 		}

// 		session := sessions.Default(c)
// 		stored := session.Get(web.SESSION_CSRF_TOKEN)
// 		received := c.GetHeader(web.HEADER_X_CSRF_TOKEN)

// 		log.Debug().Msgf("stored CSRF token: %v, received CSRF token: %v", stored, received)

// 		if stored == nil || stored != received {
// 			web.UnauthorizedResp(c, "invalid CSRF token")
// 			return
// 		}

// 		c.Next()
// 	}
// }

// Gets the JWT user claims from the context. Microservices
// should expect to find the JWT claims in the user slot.
func GetJwtUser(c *gin.Context) (*token.AuthUserJwtClaims, error) {

	v, exists := c.Get("user")

	if !exists {
		return nil, errors.New("no user in context")
	}

	user := v.(*token.AuthUserJwtClaims)

	return user, nil
}

// Enforces that there is a JWT user with permissions and calls the supplied route function with it
func JwtUserWithPermissionsRoute(c *gin.Context, r func(c *gin.Context, isAdmin bool, user *token.AuthUserJwtClaims)) {
	user, err := GetJwtUser(c)

	if err != nil {
		c.Error(err)
		return
	}

	if len(user.Permissions) == 0 {
		web.ForbiddenResp(c, auth.ErrInvalidPermissions)
		return
	}

	r(c, auth.HasAdminPermission(user.Permissions), user)
}
