package middleware

import (
	"fmt"
	"net/http"

	"github.com/antonybholmes/go-web"
	"github.com/antonybholmes/go-web/auth"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

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
