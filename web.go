package web

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"

	"github.com/antonybholmes/go-web/auth"
	"github.com/gin-gonic/gin"
)

const (
	//SESSION_PUBLICID   string = "publicId"
	//SESSION_ROLES      string = "roles"
	SESSION_USER       string = "user"
	SESSION_CSRF_TOKEN string = "csrfToken"
	SESSION_CREATED_AT string = "createdAt"
	SESSION_EXPIRES_AT string = "expiresAt"
)

const (
	CSRF_COOKIE_NAME string = "csrf_token"
)

const HEADER_X_CSRF_TOKEN = "X-CSRF-Token"

const ERROR_USER_DOES_NOT_EXIST = "user does not exist"
const ERROR_WRONG_TOKEN_TYPE = "wrong token type"

type JwtInfo struct {
	Uuid string `json:"uuid"`
	//Name  string `json:"name"`
	Type auth.TokenType `json:"type"`
	//IpAddr  string `json:"ipAddr"`
	Expires string `json:"expires"`
}

type ReqJwt struct {
	Jwt string `json:"jwt"`
}

type HTTPError struct {
	Code    int    `json:"-"`
	Message string `json:"error"`
}

func (e HTTPError) Error() string {
	return e.Message
}

func InvalidEmailReq(c *gin.Context) {
	UnauthorizedResp(c, "invalid email address")
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

func NotAdminResp(c *gin.Context) {
	ForbiddenResp(c, "user is not an admin")
}

func WrongTokentTypeReq(c *gin.Context) {
	ForbiddenResp(c, ERROR_WRONG_TOKEN_TYPE)
}

func TokenErrorResp(c *gin.Context) {
	ForbiddenResp(c, "token not generated")
}

func ForbiddenResp(c *gin.Context, message string) {
	ErrorResp(c, http.StatusForbidden, message)
}

func UnauthorizedResp(c *gin.Context, message string) {
	ErrorResp(c, http.StatusUnauthorized, message)
}

func BaseUnauthorizedResp(c *gin.Context, err error) {
	ErrorResp(c, http.StatusUnauthorized, err.Error())
}

func BaseInternalErrorResp(c *gin.Context, err error) {
	InternalErrorResp(c, err.Error())
}

func InternalErrorResp(c *gin.Context, message string) {
	ErrorResp(c, http.StatusInternalServerError, message)
}

func BadReqResp(c *gin.Context, message string) {
	ErrorResp(c, http.StatusBadRequest, message)
}

func BaseBadReqResp(c *gin.Context, err error) {
	ErrorResp(c, http.StatusBadRequest, err.Error())
}

func ErrorResp(c *gin.Context, status int, message string) {
	//c.Error(err).SetMeta(status)

	c.Error(HTTPError{
		Code:    status,
		Message: message,
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
func ParseN(c *gin.Context, defaultN uint16) uint16 {

	v := c.Query("n")

	if v == "" {
		return defaultN
	}

	n, err := strconv.Atoi(v)

	if err != nil {
		return defaultN
	}

	return uint16(n)
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

type LoginResp struct {
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

// func MakeValidResp(c *gin.Context, message string, valid bool) error {
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

func MakeCsrfTokenResp(c *gin.Context) (string, error) {
	csrfToken, err := GenerateCSRFToken()

	if err != nil {
		InternalErrorResp(c, "error generating CSRF token")
		return "", err
	}

	// Set the CSRF token in a session cookie
	http.SetCookie(c.Writer, &http.Cookie{
		Name:  CSRF_COOKIE_NAME,
		Value: csrfToken,
		Path:  "/",
		//MaxAge:   auth.MAX_AGE_30_DAYS_SECS, // 0 means until browser closes
		Secure:   true,
		HttpOnly: false, // must be readable from JS!
		SameSite: http.SameSiteNoneMode,
	})

	MakeDataResp(c, "", &CsrfTokenResp{
		CsrfToken: csrfToken,
	})

	return csrfToken, nil
}
