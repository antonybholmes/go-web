package middleware

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/antonybholmes/go-web"
	"github.com/antonybholmes/go-web/auth"
	"github.com/gin-contrib/sessions"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/golang-jwt/jwt/v5"
)

type APIError struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

func LoggingMiddleware(logger zerolog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Process the request
		c.Next()

		// Log the HTTP request details after it completes
		duration := time.Since(start)

		// Log the request information
		logger.Info().
			Str("method", c.Request.Method).
			Str("path", c.Request.URL.Path).
			Int("status", c.Writer.Status()).
			Dur("duration", duration).
			Msg("HTTP request")
	}
}

func ErrorHandlerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Create a defer function that will be called after the handler finishes
		defer func() {
			if err := recover(); err != nil {
				// Handle panic errors with 500 status code
				c.JSON(http.StatusInternalServerError, APIError{
					Code:    http.StatusInternalServerError,
					Message: fmt.Sprintf("internal server error: %v", err),
				})
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
				c.JSON(err.Code, APIError{
					Code:    err.Code,
					Message: err.Message,
				})
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
				c.JSON(status, APIError{
					Code:    status,
					Message: lastErr.Error(),
				})
			}
			c.Abort()
		}
	}
}

func ParseToken(c *gin.Context) (string, error) {
	// Get the token from the "Authorization" header
	authHeader := c.GetHeader("Authorization")

	if authHeader == "" {
		return "", fmt.Errorf("authorization header missing")
	}

	// Split the token (format: "Bearer <token>")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	if tokenString == authHeader {
		return "", fmt.Errorf("malformed token")
	}

	return tokenString, nil
}

type JWTClaimsFunc func(token string, claims jwt.Claims) error

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

// Reads the token and parses the authorization JWT. If no jwt is present, aborts access.
func JwtUserMiddleware(claimsParser JWTClaimsFunc) gin.HandlerFunc {
	return func(c *gin.Context) {

		tokenString, err := ParseToken(c)

		if err != nil {
			c.Error(err)
			c.Abort()
			return
		}

		claims := auth.TokenClaims{}

		err = claimsParser(tokenString, &claims)

		// // Parse the JWT
		// _, err = jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		// 	// Return the secret key for verifying the token
		// 	return consts.JWT_RSA_PUBLIC_KEY, nil
		// })

		if err != nil {
			c.Error(err)
			c.Abort()
			return
		}

		// use pointer to token
		c.Set("user", &claims)

		// Continue processing the request
		c.Next()

	}
}

func JwtAuth0Middleware(rsaPublicKey *rsa.PublicKey) gin.HandlerFunc {

	claimsParser := JwtClaimsRSAParser(rsaPublicKey)

	return func(c *gin.Context) {

		tokenString, err := ParseToken(c)

		if err != nil {
			web.UnauthorizedResp(c, "invalid auth0 token")
			return
		}

		claims := auth.Auth0TokenClaims{}

		//log.Debug().Msgf("token %s", tokenString)

		// Parse the JWT
		// _, err = jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		// 	// Return the secret key for verifying the token
		// 	return consts.JWT_AUTH0_RSA_PUBLIC_KEY, nil
		// })

		err = claimsParser(tokenString, &claims)

		if err != nil {
			web.UnauthorizedResp(c, "invalid auth0 token")
			return
		}

		// use pointer to token
		c.Set("user", &claims)

		// Continue processing the request
		c.Next()
	}
}

func JwtClerkMiddleware(rsaPublicKey *rsa.PublicKey) gin.HandlerFunc {
	claimsParser := JwtClaimsRSAParser(rsaPublicKey)

	return func(c *gin.Context) {

		tokenString, err := ParseToken(c)

		if err != nil {
			web.UnauthorizedResp(c, "invalid clerk token")
			return
		}

		claims := auth.ClerkTokenClaims{}

		log.Debug().Msgf("token %s", tokenString)

		// Parse the JWT
		// _, err = jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		// 	// Return the secret key for verifying the token
		// 	return consts.JWT_AUTH0_RSA_PUBLIC_KEY, nil
		// })

		err = claimsParser(tokenString, &claims)

		if err != nil {
			c.Error(err)
			c.Abort()
			return
		}

		log.Debug().Msgf("%v %s", claims, claims.Email)

		// use pointer to token
		c.Set("user", &claims)

		// Continue processing the request
		c.Next()
	}
}

func JwtSupabaseMiddleware(secret string) gin.HandlerFunc {
	claimsParser := JwtClaimsHMACParser(secret)

	return func(c *gin.Context) {

		tokenString, err := ParseToken(c)

		if err != nil {
			web.UnauthorizedResp(c, "invalid supabase token")
			return
		}

		claims := auth.SupabaseTokenClaims{}

		log.Debug().Msgf("token %s", tokenString)

		// Parse the JWT
		// _, err = jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		// 	// Return the secret key for verifying the token
		// 	return consts.JWT_AUTH0_RSA_PUBLIC_KEY, nil
		// })

		err = claimsParser(tokenString, &claims)

		if err != nil {
			c.Error(err)
			c.Abort()
			return
		}

		log.Debug().Msgf("%v %s", claims, claims.Email)

		// use pointer to token
		c.Set("user", &claims)

		// Continue processing the request
		c.Next()
	}
}

type UserClaimsFunc func(c *gin.Context, claims *auth.TokenClaims)

func checkUserExistsMiddleware(c *gin.Context, f UserClaimsFunc) {

	user, ok := c.Get("user")

	if !ok {
		web.UserDoesNotExistResp(c)

		return
	}

	claims := user.(*auth.TokenClaims)

	f(c, claims)
}

func JwtIsSpecificTokenTypeMiddleware(tokenType auth.TokenType) gin.HandlerFunc {
	return func(c *gin.Context) {
		checkUserExistsMiddleware(c, func(c *gin.Context, claims *auth.TokenClaims) {

			if claims.Type != tokenType {
				web.ForbiddenResp(c, fmt.Sprintf("wrong token type: %s, should be %s", claims.Type, tokenType))

				return
			}

			c.Next()
		})
	}
}

func JwtIsRefreshTokenMiddleware() gin.HandlerFunc {
	return JwtIsSpecificTokenTypeMiddleware(auth.REFRESH_TOKEN)
}

func JwtIsAccessTokenMiddleware() gin.HandlerFunc {
	return JwtIsSpecificTokenTypeMiddleware(auth.ACCESS_TOKEN)
}

func JwtIsUpdateTokenMiddleware() gin.HandlerFunc {
	return JwtIsSpecificTokenTypeMiddleware(auth.UPDATE_TOKEN)
}

func JwtIsVerifyEmailTokenMiddleware() gin.HandlerFunc {
	return JwtIsSpecificTokenTypeMiddleware(auth.VERIFY_EMAIL_TOKEN)
}

func JwtIsAdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		checkUserExistsMiddleware(c, func(c *gin.Context, claims *auth.TokenClaims) {

			if !auth.IsAdmin((claims.Roles)) {
				web.ForbiddenResp(c, "user is not an admin")

				return
			}

			c.Next()
		})
	}
}

func JwtCanSigninMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		checkUserExistsMiddleware(c, func(c *gin.Context, claims *auth.TokenClaims) {

			if !auth.CanSignin((claims.Roles)) {
				web.ForbiddenResp(c, "user is not allowed to login")
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

func CreateCSRFTokenCookie(c *gin.Context) (string, error) {
	token, err := web.GenerateCSRFToken()

	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return "", fmt.Errorf("failed to generate CSRF token: %w", err)
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:  web.CSRF_COOKIE_NAME,
		Value: token,
		Path:  "/",
		//Domain:   "ed.site.com", // or leave empty if called via ed.site.com
		MaxAge:   auth.MAX_AGE_30_DAYS_SECS, // 0 means until browser closes
		Secure:   true,
		HttpOnly: false, // must be readable from JS!
		SameSite: http.SameSiteNoneMode,
	})

	log.Debug().Msgf("CSRF token set in cookie: %s", token)

	return token, nil
}

func CSRFCookieMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		_, err := c.Cookie(web.CSRF_COOKIE_NAME)

		if err == nil {
			// Cookie exists, do nothing
			c.Next()
			return
		}

		log.Debug().Msgf("CSRF cookie not found, creating a new one")

		_, err = CreateCSRFTokenCookie(c)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		c.Next()
	}
}

func CSRFValidateMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}

		cookieToken, err := c.Cookie(web.CSRF_COOKIE_NAME)

		if err != nil {
			web.ForbiddenResp(c, "CSRF token missing in cookie")

			return
		}

		headerToken := c.GetHeader(web.HEADER_X_CSRF_TOKEN)

		if headerToken == "" || headerToken != cookieToken {
			web.ForbiddenResp(c, "invalid CSRF token")

			// Optionally, you can also log the error
			log.Error().Msgf("CSRF token mismatch: cookie=%s, header=%s", cookieToken, headerToken)
			return
		}

		c.Next()
	}
}

// basic check that session exists and seems to be populated with the user
func SessionIsValidMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)

		sessData, err := ReadSessionInfo(c, session)

		if err != nil {
			web.UnauthorizedResp(c, "invalid session")
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

// Create a permissions middleware to verify jwt permissions on a token
func JwtHasRoleMiddleware(validRoles ...string) gin.HandlerFunc {

	return func(c *gin.Context) {
		checkUserExistsMiddleware(c, func(c *gin.Context, claims *auth.TokenClaims) {

			//log.Debug().Msgf("claims %v", claims)

			// if we are not an admin, lets see what roles
			// we have and if they match the valid list
			if !auth.IsAdmin(claims.Roles) {
				isValidRole := false

				for _, validRole := range validRoles {

					// if we find a permission, stop and move on
					if strings.Contains(claims.Roles, validRole) {
						isValidRole = true
						break
					}

				}

				if !isValidRole {
					web.ForbiddenResp(c, "invalid role")
					return
				}
			}

			c.Next()
		})
	}
}

func JwtHasRDFRoleMiddleware() gin.HandlerFunc {
	return JwtHasRoleMiddleware("RDF")
}
