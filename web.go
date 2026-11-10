package web

import (
	"fmt"
	"io"
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

	// Default separator for concatenating multiple values in a single string, such as in cookies or keys.
	// Using a constant ensures consistency across the codebase and makes it easy to change if needed.
	Sep = "|"
)

var (
	ErrInvalidEmail     = fmt.Errorf("invalid email address")
	ErrInvalidBody      = fmt.Errorf("invalid body")
	ErrInvalidUsername  = fmt.Errorf("invalid username")
	ErrPasswordMismatch = fmt.Errorf("passwords do not match")
)

// BindQueryAndJSON binds both query parameters and JSON body to the given object.
func BindQueryAndJSON(c *gin.Context, obj any) error {
	if err := c.ShouldBindQuery(obj); err != nil {
		return err
	}

	if err := c.ShouldBindJSON(obj); err != nil && err != io.EOF {
		return err
	}
	return nil
}

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
	UnauthorizedResp(c, ErrInvalidUsername)
}

func PasswordsDoNotMatchReq(c *gin.Context) {
	UnauthorizedResp(c, ErrPasswordMismatch)
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

func ParseBoolParam(c *gin.Context, name string, defaultState bool) bool {

	v := c.Query(name)

	if v == "" {
		return defaultState
	}

	v = strings.ToLower(strings.TrimSpace(v))

	ret, err := strconv.ParseBool(v)

	if err != nil {
		return defaultState
	}

	return ret
}

func ParseOutput(c *gin.Context) string {
	v := strings.ToLower(strings.TrimSpace(c.Query("output")))

	if v == "text" {
		return "text"
	}

	return "json" // default
}

type StatusResp struct {
	Status int `json:"status"`
}

type StatusMessageResp struct {
	Message string `json:"message"`
	Status  int    `json:"status"`
}

type DataResp struct {
	Data any `json:"data"`
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

func MakeOkResp(c *gin.Context, message string) {
	MakeSuccessResp(c, message, true)
}

func MakeSuccessResp(c *gin.Context, message string, success bool) {
	MakeDataResp(c, message, &SuccessResp{Success: success})
}

// Param names that are to be normalized to lowercase and trimmed of whitespace to ensure consistency.
// e.g. "GRCh38" and "grch38" will both be treated as "grch38", and " grch38 " will also be treated as "grch38".
func FormatParam(param string) string {
	return strings.ToLower(strings.TrimSpace(param))
}
