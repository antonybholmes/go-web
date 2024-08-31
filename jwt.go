package auth

import (
	"crypto/rsa"
	"net/mail"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

type JwtType = uint

const (
	JWT_VERIFY_EMAIL   JwtType = 1
	JWT_PASSWORDLESS   JwtType = 2
	JWT_RESET_PASSWORD JwtType = 3
	JWT_CHANGE_EMAIL   JwtType = 4
	JWT_REFRESH        JwtType = 5
	JWT_ACCESS         JwtType = 6
	JWT_OTP            JwtType = 7
)

// type TokenType = string

// const (
// 	TOKEN_TYPE_VERIFY_EMAIL   TokenType = "verify_email"
// 	TOKEN_TYPE_PASSWORDLESS   TokenType = "passwordless"
// 	TOKEN_TYPE_RESET_PASSWORD TokenType = "reset_password"
// 	TOKEN_TYPE_CHANGE_EMAIL   TokenType = "change_email"
// 	TOKEN_TYPE_REFRESH        TokenType = "refresh"
// 	TOKEN_TYPE_ACCESS         TokenType = "access"
// 	TOKEN_TYPE_OTP            TokenType = "otp"
// )

const (
	JWT_TTL_YEAR    time.Duration = time.Hour * 24 * 365
	JWT_TTL_30_DAYS time.Duration = time.Hour * 24 * 30
	JWT_TTL_DAY     time.Duration = time.Hour * 24
	JWT_TTL_HOUR    time.Duration = time.Hour //time.Minute * 60
	JWT_TTL_20_MINS time.Duration = time.Minute * 20
	JWT_TTL_15_MINS time.Duration = time.Minute * 15
	JWT_TTL_10_MINS time.Duration = time.Minute * 10
)

const JWT_CLAIM_SEP = " "

type JwtCustomClaims struct {
	jwt.RegisteredClaims
	PublicId string  `json:"publicId"`
	Type     JwtType `json:"type"`
	Data     string  `json:"data,omitempty"`
	Otp      string  `json:"otp,omitempty"`
	Scope    string  `json:"scope,omitempty"`
	//Roles    []string `json:"roles,omitempty"`
	Roles string `json:"roles,omitempty"`
}

//type RoleMap map[string][]string

// type JwtResetPasswordClaims struct {
// 	Username string `json:"username"`
// 	JwtCustomClaims
// }

// type JwtUpdateEmailClaims struct {
// 	Email string `json:"email"`
// 	JwtCustomClaims
// }

// func TokenTypeString(t TokenType) string {
// 	switch t {
// 	case TOKEN_TYPE_VERIFY_EMAIL:
// 		return "verify_email_token"
// 	case TOKEN_TYPE_PASSWORDLESS:
// 		return "passwordless_token"
// 	case TOKEN_TYPE_RESET_PASSWORD:
// 		return "reset_password_token"
// 	case TOKEN_TYPE_ACCESS:
// 		return "access_token"
// 	case TOKEN_TYPE_REFRESH:
// 		return "refresh_token"
// 	default:
// 		return "other"
// 	}
// }

// Claims are space separated strings to match
// the scope spec and reduce jwt complexity
func MakeClaim(claims []string) string {
	return strings.Join(claims, JWT_CLAIM_SEP)
}

type JwtGen struct {
	secret *rsa.PrivateKey
}

func NewJwtGen(secret *rsa.PrivateKey) *JwtGen {
	return &JwtGen{secret: secret}
}

func (tc *JwtGen) RefreshJwt(c echo.Context, publicId string, roles string) (string, error) {
	return tc.BaseAuthJwt(c,
		publicId,
		JWT_REFRESH,
		roles,
		JWT_TTL_HOUR)
}

func (tc *JwtGen) AccessJwt(c echo.Context, publicId string, roles string) (string, error) {
	return tc.BaseAuthJwt(c,
		publicId,
		JWT_ACCESS,
		roles,
		JWT_TTL_15_MINS)
}

// token for all possible values
func (tc *JwtGen) BaseAuthJwt(c echo.Context,
	publicId string,
	tokenType JwtType,
	roles string,
	ttl time.Duration) (string, error) {

	claims := JwtCustomClaims{
		PublicId: publicId,
		//IpAddr:           ipAddr,
		Type:             tokenType,
		Roles:            roles,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl))},
	}

	return tc.BaseJwt(claims)
}

func (tc *JwtGen) VerifyEmailJwt(c echo.Context, publicId string) (string, error) {
	return tc.ShortTimeJwt(c,
		publicId,
		JWT_VERIFY_EMAIL)
}

func (tc *JwtGen) ResetPasswordJwt(c echo.Context, user *AuthUser) (string, error) {
	claims := JwtCustomClaims{
		PublicId: user.PublicId,
		// include first name to personalize reset
		Data:             user.FirstName,
		Type:             JWT_RESET_PASSWORD,
		Otp:              CreateOTP(user),
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(JWT_TTL_10_MINS))}}

	return tc.BaseJwt(claims)
}

func (tc *JwtGen) ResetEmailJwt(c echo.Context, user *AuthUser, email *mail.Address) (string, error) {

	claims := JwtCustomClaims{
		PublicId:         user.PublicId,
		Data:             email.Address,
		Type:             JWT_CHANGE_EMAIL,
		Otp:              CreateOTP(user),
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(JWT_TTL_20_MINS))}}

	return tc.BaseJwt(claims)

}

func (tc *JwtGen) PasswordlessJwt(c echo.Context, publicId string) (string, error) {
	return tc.ShortTimeJwt(c,
		publicId,
		JWT_PASSWORDLESS)
}

func (tc *JwtGen) OneTimeJwt(c echo.Context, user *AuthUser, tokenType JwtType) (string, error) {
	claims := JwtCustomClaims{
		PublicId:         user.PublicId,
		Type:             tokenType,
		Otp:              CreateOTP(user),
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(JWT_TTL_10_MINS))},
	}

	return tc.BaseJwt(claims)
}

// Generate short lived tokens for one time passcode use.
func (tc *JwtGen) ShortTimeJwt(c echo.Context, publicId string, tokenType JwtType) (string, error) {
	claims := JwtCustomClaims{
		PublicId:         publicId,
		Type:             tokenType,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(JWT_TTL_10_MINS))},
	}

	return tc.BaseJwt(claims)
}

func (tc *JwtGen) BaseJwt(claims jwt.Claims) (string, error) {

	// Create token with claims
	//token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Generate encoded token and send it as response.
	t, err := token.SignedString(tc.secret)

	if err != nil {
		return "", err
	}

	//log.Debug().Msgf("token %s", t)

	return t, nil
}

// Get the unique permissions associated with a user based
// on their jwt permissions
/* func RolesToPermissions(roleMap *RoleMap) []string {
	permissionSet := make(map[string]struct{})

	for role := range *roleMap {

		for _, permission := range (*roleMap)[role] {
			_, ok := permissionSet[permission]

			if !ok {
				permissionSet[permission] = struct{}{}
			}
		}
	}

	// sort
	ret := make([]string, 0, len(permissionSet))

	for permission := range permissionSet {
		ret = append(ret, permission)
	}

	sort.Strings(ret)

	return ret
} */
