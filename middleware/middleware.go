package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/antonybholmes/go-web"
	"github.com/antonybholmes/go-web/auth"
	"github.com/gin-contrib/sessions"

	"github.com/antonybholmes/go-sys/log"
	"github.com/gin-gonic/gin"
)

type (
	HttpError struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	}

	UserJWTParser struct {
		claimsParser JwtClaimsParser
	}
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
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Error().Msgf("request panic: %v\n%s", recovered, debug.Stack())
				c.Abort()

				if !c.Writer.Written() {
					c.JSON(http.StatusInternalServerError,
						NewHttpError(http.StatusInternalServerError, "internal server error"))
				}
			}
		}()

		// Continue processing the request
		c.Next()

		if len(c.Errors) == 0 {
			return
		}

		// Check if there are any errors

		// Get the last error (or you can choose how to handle multiple errors)
		err := c.Errors.Last().Err

		// If the response has already been written,
		// we cannot modify it, so we log the error and abort further processing.
		if c.Writer.Written() {
			log.Error().Msgf("request error after response started: %v", err)
			c.Abort()
			return
		}

		status := http.StatusInternalServerError
		message := "internal server error"

		var httpErr web.HTTPError

		// for handling both value and pointer types of HttpError
		var httpErrPtr *web.HTTPError

		switch {
		case errors.As(err, &httpErr):
			status, message = httpErr.Code, httpErr.Message
		case errors.As(err, &httpErrPtr) && httpErrPtr != nil:
			status, message = httpErrPtr.Code, httpErrPtr.Message
		default:
			log.Error().Msgf("unhandled request error: %v", err)
		}

		if status < 400 || status > 599 {
			log.Error().Msgf("invalid HTTP error status %d: %v", status, err)
			status = http.StatusInternalServerError
			message = "internal server error"
		}

		c.Abort()
		c.JSON(status, NewHttpError(status, message))

	}
}

// basic check that session exists and seems to be populated with the user
func SessionIsValidMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)

		sessData, err := ReadSessionInfo(c, session)

		if err != nil {
			web.UnauthorizedResp(c, auth.ErrInvalidSession)
			return
		}

		// Set user to the session data in the context
		c.Set("user", sessData.AuthUser)

		c.Next()
	}
}

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

// func JwtHasPermissionsMiddleware(permissions ...string) gin.HandlerFunc {

// 	//roleSet := sys.NewStringSet().UpdateFromList(roles)

// 	return func(c *gin.Context) {
// 		checkJWTUserExistsMiddleware(c, func(c *gin.Context, claims *token.AuthUserJwtClaims) {

// 			//log.Debug().Msgf("claims %v", claims)

// 			// if we are not an admin, lets see what roles
// 			// we have and if they match the valid list
// 			if !auth.HasAdminPermission(claims.Permissions) {

// 				found := false

// 				for _, p := range permissions {
// 					if slices.Contains(claims.Permissions, p) {
// 						found = true

// 						break
// 					}
// 				}

// 				if !found {
// 					web.ForbiddenResp(c, auth.ErrInvalidPermissions)
// 					return
// 				}
// 			}

// 			c.Next()
// 		})
// 	}
// }

// func JwtHasRDFRoleMiddleware() gin.HandlerFunc {
// 	return JwtHasRoleMiddleware("RDF")
// }

// func JwtHasRDFPermMiddleware() gin.HandlerFunc {
// 	return JwtHasPermissionsMiddleware("rdf:view")
// }

func GetUser(c *gin.Context) (*auth.AuthUser, error) {

	v, exists := c.Get("user")

	if !exists {
		return nil, errors.New("no user in context")
	}

	user := v.(*auth.AuthUser)

	return user, nil
}
