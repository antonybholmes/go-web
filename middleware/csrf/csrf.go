package csrf

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/antonybholmes/go-sys/log"
	"github.com/antonybholmes/go-web"
	"github.com/antonybholmes/go-web/auth"
	"github.com/gin-gonic/gin"
)

// type (
// 	CSRFError struct {
// 		s string
// 	}
// )

const CsrfCookieName string = "csrf-token"

var (
	ErrCSRFTokenMissing = "token missing"
	ErrCSRFTokenInvalid = "token invalid"
)

// func (e *CSRFError) Error() string {
// 	return fmt.Sprintf("csrf error: %s", e.s)
// }

// func NewCSRFError(s string) error {
// 	return &CSRFError{s}
// }

func CreateCSRFTokenCookie(c *gin.Context) (string, error) {
	token, err := GenerateCSRFToken()

	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return "", fmt.Errorf("failed to generate CSRF token: %w", err)
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:  CsrfCookieName,
		Value: token,
		Path:  "/",
		//Domain:   "ed.site.com", // or leave empty if called via ed.site.com
		MaxAge:   auth.MaxAge30DaysSecs, // 0 means until browser closes
		Secure:   true,
		HttpOnly: false, // must be readable from JS!
		SameSite: http.SameSiteNoneMode,
	})

	log.Debug().Msgf("CSRF token set in cookie: %s", token)

	return token, nil
}

func CSRFCookieMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		_, err := c.Cookie(CsrfCookieName)

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

		cookieToken, err := c.Cookie(CsrfCookieName)

		if err != nil {
			web.ForbiddenResp(c, ErrCSRFTokenMissing)
			return
		}

		parts := strings.Split(cookieToken, "|")

		if len(parts) < 2 {
			web.ForbiddenResp(c, ErrCSRFTokenInvalid)
			return
		}

		csrfToken := parts[0]

		if csrfToken == "" {
			web.ForbiddenResp(c, ErrCSRFTokenInvalid)
			return
		}

		headerToken := c.GetHeader(web.HeaderXCsrfToken)

		if headerToken == "" || headerToken != csrfToken {
			web.ForbiddenResp(c, ErrCSRFTokenInvalid)

			// Optionally, you can also log the error
			log.Error().Msgf("CSRF token mismatch: cookie=%s, header=%s", csrfToken, headerToken)
			return
		}

		c.Next()
	}
}

func GenerateCSRFToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	// make cookie safe
	return base64.RawURLEncoding.EncodeToString(b), nil //StdEncoding
}

type CsrfTokenResp struct {
	CsrfToken string `json:"csrfToken"`
}

func MakeNewCSRFTokenResp(c *gin.Context) (string, error) {
	var csrfToken string
	needNewToken := true

	cookie, err := c.Cookie(CsrfCookieName)

	if err == nil {
		parts := strings.Split(cookie, "|")

		if len(parts) > 1 {
			csrfToken = parts[0]
			timestampStr := parts[1]

			timestamp, err := time.Parse(time.RFC3339, timestampStr)

			if err == nil {
				if time.Since(timestamp) < auth.Ttl10Mins {
					needNewToken = false
				}
			}
		}
	}

	if needNewToken {
		csrfToken, err := GenerateCSRFToken()

		if err != nil {
			web.InternalErrorResp(c, fmt.Sprintf("error generating CSRF token: %v", err))
			return "", err
		}

		now := time.Now().UTC()

		// Set the CSRF token in a session cookie
		http.SetCookie(c.Writer, &http.Cookie{
			Name: CsrfCookieName,
			// include timestamp in cookie so we can check age. Since cookie
			// has expire time, even if user tries to modify timestamp, cookie will
			// eventually expire.
			Value:    fmt.Sprintf("%s|%s", csrfToken, now.Format(time.RFC3339)),
			Path:     "/",
			MaxAge:   int(auth.Ttl10Mins.Seconds()),
			Secure:   true,
			HttpOnly: false, // must be readable from JS!
			SameSite: http.SameSiteNoneMode,
			//Expires:  now.Add(auth.Ttl10Mins),
		})
	}

	web.MakeDataResp(c, "", &CsrfTokenResp{
		CsrfToken: csrfToken,
	})

	return csrfToken, nil
}
