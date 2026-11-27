package web

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/vmihailenco/msgpack/v5"
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

	AboutResp struct {
		Name      string `json:"name"`
		Copyright string `json:"copyright"`
		Version   string `json:"version"`
		Updated   string `json:"updated"`
		Build     int    `json:"build"`
	}

	InfoResp struct {
		IpAddr string `json:"ipAddr"`
		Arch   string `json:"arch"`
	}

	// LowerString automatically normalizes bound values to lowercase.
	LowerString string
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

	MimeTypeZip = "application/zip"

	HeaderContentType        = "Content-Type"
	HeaderContentDisposition = "Content-Disposition"
)

var (
	ErrInvalidEmail     = fmt.Errorf("invalid email address")
	ErrInvalidBody      = fmt.Errorf("invalid body")
	ErrInvalidUsername  = fmt.Errorf("invalid username")
	ErrPasswordMismatch = fmt.Errorf("passwords do not match")

	// For validating alphanumeric params, allow dash for uuids
	IsAlphanumericRegex = regexp.MustCompile(`^[a-zA-Z0-9\-]+$`)
)

func (l *LowerString) UnmarshalText(text []byte) error {
	*l = LowerString(strings.ToLower(strings.TrimSpace(string(text))))
	return nil
}

func (l LowerString) String() string {
	return string(l)
}

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
	Status int `json:"status" msgpack:"status"`
}

type StatusMessageResp struct {
	Message string `json:"message" msgpack:"message"`
	Status  int    `json:"status" msgpack:"status"`
}

type DataResp struct {
	Data any `json:"data" msgpack:"data"`
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
			Status:  http.StatusOK,
			Message: message,
			Data:    data,
		})
}

func MakeAcceptedResp[V any](c *gin.Context, message string, data V) {
	c.JSON(
		http.StatusAccepted,
		DataResp{
			Status:  http.StatusAccepted,
			Message: message,
			Data:    data,
		})
}

func MakeMsgpackResp[V any](c *gin.Context, message string, data V) {
	resp := DataResp{
		Status:  http.StatusOK,
		Message: message,
		Data:    data,
	}

	encoded, err := msgpack.Marshal(resp)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to encode response",
		})
		return
	}
	c.Data(http.StatusOK, "application/msgpack", encoded)
}

func MakeOkResp(c *gin.Context, message string) {
	MakeSuccessResp(c, message, true)
}

func MakeSuccessResp(c *gin.Context, message string, success bool) {
	MakeDataResp(c, message, &SuccessResp{Success: success})
}

func FormatParam(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))

	if !IsAlphanumericRegex.MatchString(v) {
		return "", fmt.Errorf("invalid parameter: %s", v)
	}

	return v, nil
}

// Param names that are to be normalized to lowercase and trimmed of whitespace to ensure consistency.
// e.g. "GRCh38" and "grch38" will both be treated as "grch38", and " grch38 " will also be treated as "grch38".
func FormatQuery(c *gin.Context, key string) (string, error) {
	return FormatParam(c.Query(key))
}

func SplitFormatParam(v string) ([]string, error) {
	v = strings.TrimSpace(v)

	if v == "" {
		return []string{}, nil
	}

	parts := strings.Split(v, ",")
	formatted := make([]string, len(parts))
	for i, part := range parts {
		fp, err := FormatParam(part)
		if err != nil {
			return nil, err
		}
		formatted[i] = fp
	}
	return formatted, nil
}

// Returns values of comma-separated parameters after formatting each one.
func SplitFormatQuery(c *gin.Context, key string) ([]string, error) {
	return SplitFormatParam(c.Query(key))
}

func IntParam(v string) (int, error) {
	v = strings.TrimSpace(v)

	if v == "" {
		return 0, fmt.Errorf("parameter is empty")
	}

	num, err := strconv.Atoi(v)

	if err != nil {
		return 0, fmt.Errorf("invalid number: %s", v)
	}

	return num, nil
}

func IntQuery(c *gin.Context, key string) (int, error) {
	return IntParam(c.Query(key))
}

func FloatQuery(c *gin.Context, key string) (float64, error) {
	param := strings.TrimSpace(c.Query(key))

	if param == "" {
		return 0, fmt.Errorf("parameter is empty")
	}

	num, err := strconv.ParseFloat(param, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number: %s", param)
	}

	return num, nil
}

func BoolQuery(c *gin.Context, key string) bool {
	param := strings.ToLower(strings.TrimSpace(c.Query(key)))

	return param == "t" || param == "true" || param == "1"
}

func SplitIntQuery(c *gin.Context, key string) ([]int, error) {
	param := strings.TrimSpace(c.Query(key))

	if param == "" {
		return []int{}, nil
	}

	parts := strings.Split(param, ",")
	ints := make([]int, len(parts))
	for i, part := range parts {
		num, err := IntParam(part)
		if err != nil {
			return nil, err
		}
		ints[i] = num
	}
	return ints, nil
}
