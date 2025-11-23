package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

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
	SessionUser      = "user"
	SessionCsrfToken = "csrfToken"
	SessionCreatedAt = "createdAt"
	SessionExpiresAt = "expiresAt"

	//CsrfMaxAgeMins   time.Duration = time.Minute * 10
	HeaderXCsrfToken = "X-CSRF-Token"
)

var (
	ErrInvalidEmail = "invalid email address"
	ErrInvalidBody  = "invalid body"
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
	ForbiddenResp(c, "email address not verified")
}

func UserDoesNotExistResp(c *gin.Context) {
	UnauthorizedResp(c, "user does not exist")
}

func UserNotAllowedToSignInErrorResp(c *gin.Context) {
	ForbiddenResp(c, "user not allowed to sign in")
}

func InvalidUsernameReq(c *gin.Context) {
	UnauthorizedResp(c, "invalid username")
}

func PasswordsDoNotMatchReq(c *gin.Context) {
	UnauthorizedResp(c, "passwords do not match")
}

func ForbiddenResp(c *gin.Context, err string) {
	ErrorResp(c, http.StatusForbidden, err)
}

func UnauthorizedResp(c *gin.Context, err string) {
	ErrorResp(c, http.StatusUnauthorized, err)
}

func InternalErrorResp(c *gin.Context, err string) {
	ErrorResp(c, http.StatusInternalServerError, err)
}

func BadReqResp(c *gin.Context, err string) {
	ErrorResp(c, http.StatusBadRequest, err)
}

func TooManyRequestsResp(c *gin.Context, err string) {
	ErrorResp(c, http.StatusTooManyRequests, err)
}

func ErrorResp(c *gin.Context, status int, err string) {
	//c.Error(err).SetMeta(status)

	c.Error(HTTPError{
		Code:    status,
		Message: err,
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
func ParseN(c *gin.Context, defaultN int) int {
	return ParseNumParam(c, "n", defaultN)
}

func ParseNumParam(c *gin.Context, name string, defaultN int) int {

	v := c.Query(name)

	if v == "" {
		return defaultN
	}

	n, err := strconv.Atoi(v)

	if err != nil {
		return defaultN
	}

	return n
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
