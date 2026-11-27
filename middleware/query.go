package middleware

import (
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

// LowercaseQueryKeysMiddleware converts all query parameter keys to lowercase.
func LowercaseQueryKeysMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		rawQuery := c.Request.URL.RawQuery
		if rawQuery == "" {
			c.Next()
			return
		}

		values := c.Request.URL.Query()
		normalized := make(url.Values, len(values))

		for k, v := range values {
			lowerKey := strings.ToLower(k)
			// Append preserves multiple values if both ?tag=a and ?Tag=b were sent
			normalized[lowerKey] = append(normalized[lowerKey], v...)
		}

		c.Request.URL.RawQuery = normalized.Encode()
		c.Next()
	}
}
