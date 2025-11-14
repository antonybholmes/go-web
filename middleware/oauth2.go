package middleware

import (
	"crypto/rsa"
	"errors"

	"github.com/antonybholmes/go-sys/log"
	"github.com/antonybholmes/go-web"
	"github.com/antonybholmes/go-web/auth"
	"github.com/gin-gonic/gin"
)

var (
	ErrInvalidAuth0Token    = errors.New("invalid auth0 token")
	ErrInvalidClerkToken    = errors.New("invalid clerk token")
	ErrInvalidSupabaseToken = errors.New("invalid supabase token")
)

func JwtAuth0Middleware(rsaPublicKey *rsa.PublicKey) gin.HandlerFunc {

	claimsParser := JwtClaimsRSAParser(rsaPublicKey)

	return func(c *gin.Context) {

		tokenString, err := ParseToken(c)

		if err != nil {
			web.UnauthorizedResp(c, ErrInvalidAuth0Token)
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
			web.UnauthorizedResp(c, ErrInvalidAuth0Token)
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
			web.UnauthorizedResp(c, ErrInvalidClerkToken)
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
			web.UnauthorizedResp(c, ErrInvalidSupabaseToken)
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
