package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/antonybholmes/go-web/auth"
	"github.com/gin-gonic/gin"
)

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

func InvalidEmailReq(c *gin.Context) {
	ErrorResp(c, "invalid email address")
}

func EmailNotVerifiedReq(c *gin.Context) {
	ErrorResp(c, "email address not verified")
}

func UserDoesNotExistResp(c *gin.Context) {
	ErrorResp(c, "user does not exist")
}

func UserNotAllowedToSignIn(c *gin.Context) {
	ErrorResp(c, "user not allowed to sign in")
}

func InvalidUsernameReq(c *gin.Context) {
	ErrorResp(c, "invalid username")
}

func PasswordsDoNotMatchReq(c *gin.Context) {
	ErrorResp(c, "passwords do not match")
}

func NotAdminResp(c *gin.Context) {
	ErrorResp(c, "user is not an admin")
}

func WrongTokentTypeReq(c *gin.Context) {
	ErrorResp(c, ERROR_WRONG_TOKEN_TYPE)
}

func TokenErrorResp(c *gin.Context) {
	ErrorResp(c, "token not generated")
}

func ErrorResp(c *gin.Context, message string) {
	c.Error(fmt.Errorf("%s", message))
	c.Abort()
}

func AuthErrorResp(c *gin.Context, message string) {
	c.Error(fmt.Errorf("%s", message))
	c.Errors.Last().SetMeta(http.StatusUnauthorized)
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

func ParseN(c *gin.Context, defaultN uint16) uint16 {

	v := c.Query("n")

	if v == "" {
		return defaultN
	}

	n, err := strconv.ParseUint(v, 10, 0)

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

type LoginResp struct {
	RefreshToken string `json:"refreshToken"`
	AccessToken  string `json:"accessToken"`
}

func JsonResp[V any](c *gin.Context, status int, data V) {
	c.JSON(status, data)
}

// func MakeBadResp(c *gin.Context, err error) error {
// 	return JsonRep(c, http.StatusBadRequest, StatusResp{StatusResp: StatusResp{Status: http.StatusBadRequest}, Message: err.Error()})
// }

func MakeDataResp[V any](c *gin.Context, message string, data V) {
	JsonResp(c,
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
