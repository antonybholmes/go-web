package web

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type (
	ReqJwt struct {
		Jwt string `json:"jwt"`
	}

	ConnectionError struct {
		Message string
	}

	HTTPError struct {
		Message string `json:"error"`
		Code    int    `json:"-"`
	}
)

const (
	//SESSION_PUBLICID   string = "publicId"
	//SESSION_ROLES      string = "roles"
	SessionUser      string        = "user"
	SessionCsrfToken string        = "csrfToken"
	SessionCreatedAt string        = "createdAt"
	SessionExpiresAt string        = "expiresAt"
	CsrfCookieName   string        = "csrf_token"
	CsrfMaxAgeMins   time.Duration = time.Minute * 10
	HeaderXCsrfToken string        = "X-CSRF-Token"
)

var (
	ErrInvalidEmail = errors.New("invalid email address")
	ErrInvalidBody  = errors.New("invalid body")
)

// type JwtInfo struct {
// 	Uuid string `json:"uuid"`
// 	//Name  string `json:"name"`
// 	Type auth.TokenType `json:"type"`
// 	//IpAddr  string `json:"ipAddr"`
// 	Expires string `json:"expires"`
// }

func (e HTTPError) Error() string {
	return e.Message
}

func (e *ConnectionError) Error() string {
	return fmt.Sprintf("connection error: %s", e.Message)
}

func NewConnectionError(message string) *ConnectionError {
	return &ConnectionError{Message: message}
}

func IsConnectionError(err error) bool {
	_, ok := err.(*ConnectionError)
	return ok
}

func InvalidEmailReq(c *gin.Context) {
	UnauthorizedResp(c, ErrInvalidEmail)
}

func EmailNotVerifiedReq(c *gin.Context) {
	ForbiddenResp(c, fmt.Errorf("email address not verified"))
}

func UserDoesNotExistResp(c *gin.Context) {
	UnauthorizedResp(c, fmt.Errorf("user does not exist"))
}

func UserNotAllowedToSignInErrorResp(c *gin.Context) {
	ForbiddenResp(c, fmt.Errorf("user not allowed to sign in"))
}

func InvalidUsernameReq(c *gin.Context) {
	UnauthorizedResp(c, fmt.Errorf("invalid username"))
}

func PasswordsDoNotMatchReq(c *gin.Context) {
	UnauthorizedResp(c, fmt.Errorf("passwords do not match"))
}

func ForbiddenResp(c *gin.Context, err error) {
	ErrorResp(c, http.StatusForbidden, err)
}

func UnauthorizedResp(c *gin.Context, err error) {
	ErrorResp(c, http.StatusUnauthorized, err)
}

func InternalErrorResp(c *gin.Context, err error) {
	ErrorResp(c, http.StatusInternalServerError, err)
}

func BadReqResp(c *gin.Context, err error) {
	ErrorResp(c, http.StatusBadRequest, err)
}

func TooManyRequestsResp(c *gin.Context, err error) {
	ErrorResp(c, http.StatusTooManyRequests, err)
}

func ErrorResp(c *gin.Context, status int, err error) {
	//c.Error(err).SetMeta(status)

	c.Error(HTTPError{
		Code:    status,
		Message: err.Error(),
	})
	c.Abort()
}

// parsedLocation takes an echo context and attempts to extract parameters
// from the query string and return the location to check, the assembly
// (e.g. grch38) to search, the level of detail (1=gene,2=transcript,3=exon).
// If parameters are not provided defaults are used, but if parameters are
// considered invalid, it will throw an error.

// func parseAssembly(c *gin.Context) string {
// 	assembly := DEFAULT_ASSEMBLY

// 	v := c.Query("assembly")

// 	if v != "" {
// 		assembly = v
// 	}

// 	return assembly
// }

// parses an "n" query param as an unsigned int returning
// a default if the param is not present
func ParseN(c *gin.Context, defaultN uint) uint {
	return ParseNumParam(c, "n", defaultN)
}

func ParseNumParam(c *gin.Context, name string, defaultN uint) uint {

	v := c.Query(name)

	if v == "" {
		return defaultN
	}

	n, err := strconv.Atoi(v)

	if err != nil {
		return defaultN
	}

	return uint(n)
}

func ParseOutput(c *gin.Context) string {

	v := c.Query("output")

	if strings.Contains(strings.ToLower(v), "text") {
		return "text"
	} else {
		return "json"
	}
}

type StatusResp struct {
	Status int `json:"status"`
}

type StatusMessageResp struct {
	Message string `json:"message"`
	Status  int    `json:"status"`
}

type DataResp struct {
	Data interface{} `json:"data"`
	StatusMessageResp
}

type SuccessResp struct {
	Success bool `json:"success"`
}

type ValidResp struct {
	Valid bool `json:"valid"`
}

type JwtResp struct {
	Jwt string `json:"jwt"`
}

type RefreshTokenResp struct {
	RefreshToken string `json:"refreshToken"`
}

type AccessTokenResp struct {
	AccessToken string `json:"accessToken"`
}

type TokenResp struct {
	Token string `json:"token"`
}

type SignInResp struct {
	RefreshToken string `json:"refreshToken"`
	AccessToken  string `json:"accessToken"`
}

// func JsonResp[V any](c *gin.Context, status int, data V) {
// 	c.JSON(status, data)
// }

// func MakeBadResp(c *gin.Context, err error) error {
// 	return JsonRep(c, http.StatusBadRequest, StatusResp{StatusResp: StatusResp{Status: http.StatusBadRequest}, Message: err.Error()})
// }

func MakeDataResp[V any](c *gin.Context, message string, data V) {
	c.JSON(
		http.StatusOK,
		DataResp{
			StatusMessageResp: StatusMessageResp{
				Status:  http.StatusOK,
				Message: message,
			},
			Data: data,
		})
}

// func MakeValidResp(c *gin.Context, message error, valid bool) error {
// 	return MakeDataResp(c, message, &ValidResp{Valid: valid})
// }

func MakeOkResp(c *gin.Context, message string) {
	MakeSuccessResp(c, message, true)
}

func MakeSuccessResp(c *gin.Context, message string, success bool) {
	MakeDataResp(c, message, &SuccessResp{Success: success})
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

	cookie, err := c.Request.Cookie(CsrfCookieName)

	if err == nil && cookie != nil {
		parts := strings.Split(cookie.Value, "|")

		if len(parts) > 1 {
			csrfToken = parts[0]
			timestampStr := parts[1]

			timestampInt, err := time.Parse(time.RFC3339, timestampStr)

			if err == nil {
				if time.Since(timestampInt) < CsrfMaxAgeMins {
					needNewToken = false
				}
			}
		}
	}

	if needNewToken {
		csrfToken, err := GenerateCSRFToken()

		if err != nil {
			InternalErrorResp(c, fmt.Errorf("error generating CSRF token: %w", err))
			return "", err
		}

		timestampStr := time.Now().UTC().Format(time.RFC3339)

		// Set the CSRF token in a session cookie
		http.SetCookie(c.Writer, &http.Cookie{
			Name:  CsrfCookieName,
			Value: fmt.Sprintf("%s|%s", csrfToken, timestampStr),
			Path:  "/",
			//MaxAge:   auth.MAX_AGE_30_DAYS_SECS, // 0 means until browser closes
			Secure:   true,
			HttpOnly: false, // must be readable from JS!
			SameSite: http.SameSiteNoneMode,
			Expires:  time.Now().UTC().Add(CsrfMaxAgeMins),
		})
	}

	MakeDataResp(c, "", &CsrfTokenResp{
		CsrfToken: csrfToken,
	})

	return csrfToken, nil
}
