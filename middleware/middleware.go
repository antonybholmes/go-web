package middleware

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/antonybholmes/go-web"
	"github.com/antonybholmes/go-web/auth"
	"github.com/gin-contrib/sessions"

	"github.com/antonybholmes/go-sys/log"
	"github.com/gin-gonic/gin"

	"github.com/golang-jwt/jwt/v5"
)

type (
	HttpError struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	}

	JWTClaimsFunc func(token string, claims jwt.Claims) error
)

// NewHttpError creates a new HttpError with the given message and code
func NewHttpError(code int, message string) error {
	return &HttpError{
		Code:    code,
		Message: message,
	}
}

func (e *HttpError) Error() string {
	return fmt.Sprintf("http error: (%d) %s", e.Code, e.Message)
}

// func LoggingMiddleware(logger zerolog.Logger) gin.HandlerFunc {
func LoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Process the request
		c.Next()

		// Log the HTTP request details after it completes
		duration := time.Since(start)

		// Log the request information
		log.Info().Msgf("HTTP request: %s %s %d %v", c.Request.Method, c.Request.URL.Path, c.Writer.Status(), duration)
	}
}

func ErrorHandlerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Create a defer function that will be called after the handler finishes
		defer func() {
			if err := recover(); err != nil {
				// Handle panic errors with 500 status code
				c.JSON(http.StatusInternalServerError, NewHttpError(http.StatusInternalServerError,
					fmt.Sprintf("panic caused by %v", err),
				))
			}
		}()

		// Continue processing the request
		c.Next()

		// Check if there are any errors
		if len(c.Errors) > 0 {
			// Get the last error (or you can choose how to handle multiple errors)
			lastErr := c.Errors.Last()

			switch err := lastErr.Err.(type) {
			case web.HTTPError:
				//c.JSON(err.Code, gin.H{"error": err.Message})
				c.JSON(err.Code, NewHttpError(err.Code, err.Message))
			default:
				// Set a custom status code based on the error
				// If no custom status code is set, use the error's default status or fallback to 400
				status := http.StatusBadRequest

				//log.Debug().Msgf("error %v %d", err, err.Meta)

				if lastErr.Meta != nil {
					// ok indicates cast worked
					customStatus, ok := lastErr.Meta.(int)

					if ok {
						status = customStatus
					}
				}

				// Send the error response with custom status code
				c.JSON(status, NewHttpError(status, lastErr.Error()))
			}
			c.Abort()
		}
	}
}

func JwtClaimsRSAParser(rsaPublicKey *rsa.PublicKey) JWTClaimsFunc {
	return func(token string, claims jwt.Claims) error {
		// Parse the JWT
		_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			// Return the secret key for verifying the token
			return rsaPublicKey, nil
		})

		return err
	}
}

func JwtClaimsHMACParser(secret string) JWTClaimsFunc {
	hmacSecret := []byte(secret)

	return func(token string, claims jwt.Claims) error {
		// Parse the JWT
		_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)

			if !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return hmacSecret, nil
		})

		return err
	}
}

// Reads the token and parses the authorization JWT. If no jwt is present, returns an error.
func ParseUserJWT(claimsParser JWTClaimsFunc) func(c *gin.Context) (*auth.AuthUserJwtClaims, error) {
	return func(c *gin.Context) (*auth.AuthUserJwtClaims, error) {

		tokenString, err := auth.ParseToken(c)

		if err != nil {
			return nil, err
		}

		claims := auth.AuthUserJwtClaims{}

		err = claimsParser(tokenString, &claims)

		if err != nil {
			return nil, err
		}

		return &claims, nil
	}
}

// Reads the token and parses the authorization JWT. If no jwt is present, aborts access.
// If jwt is present it is added to the context as "user", thus subsequent handlers can
// access it.
func UserJWTMiddleware(claimsParser JWTClaimsFunc) gin.HandlerFunc {
	parseFunc := ParseUserJWT(claimsParser)

	return func(c *gin.Context) {

		claims, err := parseFunc(c)

		if err != nil {
			c.Error(err)
			c.Abort()
			return
		}

		// // Parse the JWT
		// _, err = jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		// 	// Return the secret key for verifying the token
		// 	return consts.JWT_RSA_PUBLIC_KEY, nil
		// })

		// use pointer to token
		c.Set("user", claims)

		// Continue processing the request
		c.Next()
	}
}

// checks that user exists in context and calls f with the claims
// if it does.
func checkJWTUserExistsMiddleware(c *gin.Context, f func(c *gin.Context, claims *auth.AuthUserJwtClaims)) {

	// user is a jwt
	user, err := GetJwtUser(c)

	if err != nil {
		web.UserDoesNotExistResp(c)
		return
	}

	f(c, user)
}

func JWTIsSpecificTypeMiddleware(tokenType auth.TokenType) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Debug().Msgf("Handler: %s", c.FullPath())

		checkJWTUserExistsMiddleware(c, func(c *gin.Context, claims *auth.AuthUserJwtClaims) {

			if claims.Type != tokenType {
				web.ForbiddenResp(c, fmt.Errorf("wrong token type: %s, should be %s", claims.Type, tokenType))

				return
			}

			c.Next()
		})
	}
}

func JwtIsRefreshTokenMiddleware() gin.HandlerFunc {
	return JWTIsSpecificTypeMiddleware(auth.TokenTypeRefresh)
}

// make sure the supplied token is an access token
func JwtIsAccessTokenMiddleware() gin.HandlerFunc {
	return JWTIsSpecificTypeMiddleware(auth.TokenTypeAccess)
}

func JwtIsUpdateTokenMiddleware() gin.HandlerFunc {
	return JWTIsSpecificTypeMiddleware(auth.TokenTypeUpdate)
}

func JwtIsVerifyEmailTokenMiddleware() gin.HandlerFunc {
	return JWTIsSpecificTypeMiddleware(auth.TokenTypeVerifyEmail)
}

func JwtIsAdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		checkJWTUserExistsMiddleware(c, func(c *gin.Context, claims *auth.AuthUserJwtClaims) {

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
		checkJWTUserExistsMiddleware(c, func(c *gin.Context, claims *auth.AuthUserJwtClaims) {

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

// basic check that session exists and seems to be populated with the user
func SessionIsValidMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)

		sessData, err := ReadSessionInfo(c, session)

		if err != nil {
			web.UnauthorizedResp(c, auth.ErrInvalidSession)
			return
		}

		c.Set("user", sessData.AuthUser)

		c.Next()
	}
}

// func ValidateJwtMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
// 	return func(c *gin.Context) {
// 		authorizationHeader := c.Request().Header.Get("authorization")

// 		if len(authorizationHeader) == 0 {
// 			return routes.AuthErrorReq("missing Authentication header")

// 		}

// 		log.Debug().Msgf("parsing authentication header")

// 		authPair := strings.SplitN(authorizationHeader, " ", 2)

// 		if len(authPair) != 2 {
// 			return routes.AuthErrorReq("wrong Authentication header definiton")
// 		}

// 		headerAuthScheme := authPair[0]
// 		headerAuthToken := authPair[1]

// 		if headerAuthScheme != "Bearer" {
// 			return routes.AuthErrorReq("wrong Authentication header definiton")
// 		}

// 		log.Debug().Msgf("validating JWT token")

// 		token, err := validateJwtToken(headerAuthToken)

// 		if err != nil {
// 			return routes.AuthErrorReq(err)
// 		}

// 		log.Debug().Msgf("JWT token is valid")
// 		c.Set("user", token)
// 		return next(c)

// 	}
// }

// Create a permissions middleware to verify jwt roles on a token
// func JwtHasRoleMiddleware(roles ...string) gin.HandlerFunc {

// 	//roleSet := sys.NewStringSet().UpdateFromList(roles)

// 	return func(c *gin.Context) {
// 		checkJWTUserExistsMiddleware(c, func(c *gin.Context, claims *auth.AuthUserJwtClaims) {

// 			//log.Debug().Msgf("claims %v", claims)

// 			// if we are not an admin, lets see what roles
// 			// we have and if they match the valid list
// 			if !auth.HasAdminRole(claims.Roles) {
// 				userRoles := sys.NewStringSet().ListUpdate(auth.FlattenRoles(claims.Roles))

// 				if !userRoles.ListContains(roles) {
// 					web.ForbiddenResp(c, auth.ErrInvalidRoles)
// 					return
// 				}
// 			}

// 			c.Next()
// 		})
// 	}
// }

func JwtHasPermissionsMiddleware(permissions ...string) gin.HandlerFunc {

	//roleSet := sys.NewStringSet().UpdateFromList(roles)

	return func(c *gin.Context) {
		checkJWTUserExistsMiddleware(c, func(c *gin.Context, claims *auth.AuthUserJwtClaims) {

			//log.Debug().Msgf("claims %v", claims)

			// if we are not an admin, lets see what roles
			// we have and if they match the valid list
			if !auth.HasAdminPermission(claims.Permissions) {

				found := false

				for _, p := range permissions {
					if slices.Contains(claims.Permissions, p) {
						found = true

						break
					}
				}

				if !found {
					web.ForbiddenResp(c, auth.ErrInvalidPermissions)
					return
				}
			}

			c.Next()
		})
	}
}

// func JwtHasRDFRoleMiddleware() gin.HandlerFunc {
// 	return JwtHasRoleMiddleware("RDF")
// }

func JwtHasRDFPermMiddleware() gin.HandlerFunc {
	return JwtHasPermissionsMiddleware("rdf:view")
}

// Gets the JWT user from the context. Microservices
// should expect to find the JWT claims in the user slot.
func GetJwtUser(c *gin.Context) (*auth.AuthUserJwtClaims, error) {

	v, exists := c.Get("user")

	if !exists {
		return nil, errors.New("no user in context")
	}

	user := v.(*auth.AuthUserJwtClaims)

	return user, nil
}

// Get the JWT user and call the supplied route function with it jwt is valid
func JwtUserRoute(c *gin.Context, r func(c *gin.Context, isAdmin bool, user *auth.AuthUserJwtClaims)) {
	user, err := GetJwtUser(c)

	if err != nil {
		c.Error(err)
		return
	}

	r(c, auth.HasAdminPermission(user.Permissions), user)
}

func GetUser(c *gin.Context) (*auth.AuthUser, error) {

	v, exists := c.Get("user")

	if !exists {
		return nil, errors.New("no user in context")
	}

	user := v.(*auth.AuthUser)

	return user, nil
}
