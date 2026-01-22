package auth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/antonybholmes/go-sys"
	"github.com/antonybholmes/go-web"
	"github.com/gin-gonic/gin"
	"github.com/xyproto/randomstring"
	"golang.org/x/crypto/bcrypt"
)

type (
	AccountError struct {
		s string
	}

	UrlReq struct {
		Url string `json:"url"`
	}

	RedirectUrlReq struct {
		// the url that should form the email link in any emails that are sent
		//Url string `json:"url"`
		// The url the callback url should redirect to once it completes
		RedirectUrl string `json:"redirectUrl"`
	}
)

const (
	MaxAgeYearSecs   = 31536000
	MaxAge30DaysSecs = 2592000
	MaxAge7DaysSecs  = 604800 //86400 * 7
	MaxAgeDaysSecs   = 86400

	TtlHour   time.Duration = time.Hour
	TtlDay    time.Duration = TtlHour * 24
	TtlYear   time.Duration = TtlDay * 365
	Ttl30Days time.Duration = TtlDay * 30

	Ttl1Min   time.Duration = time.Minute
	Ttl5Mins  time.Duration = time.Minute * 5
	Ttl10Mins time.Duration = time.Minute * 10
	Ttl20Mins time.Duration = time.Minute * 20
	Ttl15Mins time.Duration = time.Minute * 15
)

var (
	ErrUserDoesNotExist            = NewAccountError("user does not exist")
	ErrPasswordsDoNotMatch         = NewAccountError("passwords do not match")
	ErrPasswordDoesNotMeetCriteria = NewAccountError("password does not meet criteria")
	ErrCouldNotUpdatePassword      = NewAccountError("could not update password")
	ErrUserIsNotAdmin              = NewAccountError("user is not an admin")
	ErrUserIsNotSuper              = NewAccountError("user is not a super user")
	ErrUserCannotLogin             = NewAccountError("user is not allowed to login")
	ErrInvalidSession              = NewAccountError("invalid session")
	ErrInvalidRoles                = NewAccountError("invalid roles")
	ErrInvalidPermissions          = NewAccountError("invalid permissions")
	ErrWrongTokenType              = NewAccountError("wrong token type")
	ErrEmailNotVerified            = NewAccountError("email not verified")
	ErrInvalidUsername             = NewAccountError("invalid username")
	ErrCreatingSession             = NewAccountError("error creating session")
)

// The admin view adds roles to each user as it is assumed this
// will be used for listing users for an admin dashboard where you
// may need to know every user's roles. A standard user view does not
// include roles and these are instead expected to be derived from
// the access jwt assigned to the user since this contains their
// encoded roles and is more resilient to tampering
// type AuthUserAdminView struct {
// 	Roles []string `json:"roles" db:"role"`
// 	AuthUser
// }

// func (user *AuthUser) Address() *mail.Address {
// 	return &mail.Address{Name: user.Name, Address: user.Email}
// }

func init() {
	randomstring.Seed()
}

//
// errors
//

func NewAccountError(s string) *AccountError {
	return &AccountError{s}
}

func (e *AccountError) Error() string {
	return fmt.Sprintf("account error: %s", e.s)
}

func NewUserNotFoundError(s string) *AccountError {
	return NewAccountError(fmt.Sprintf("%s not found", s))
}

func EmailNotVerifiedReq(c *gin.Context) {
	web.ForbiddenResp(c, ErrEmailNotVerified)
}

func UserDoesNotExistResp(c *gin.Context) {
	web.UnauthorizedResp(c, ErrUserDoesNotExist)
}

func UserNotAllowedToSignInErrorResp(c *gin.Context) {
	web.ForbiddenResp(c, ErrUserCannotLogin)
}

func InvalidUsernameReq(c *gin.Context) {
	web.UnauthorizedResp(c, ErrInvalidUsername)
}

func PasswordsDoNotMatchReq(c *gin.Context) {
	web.UnauthorizedResp(c, ErrPasswordsDoNotMatch)
}

func NotAdminResp(c *gin.Context) {
	web.ForbiddenResp(c, ErrUserIsNotAdmin)
}

func WrongTokenTypeReq(c *gin.Context) {
	web.ForbiddenResp(c, ErrWrongTokenType)
}

func TokenErrorResp(c *gin.Context) {
	web.ForbiddenResp(c, errors.New("token not generated"))
}

// func NewAuthUser(
// 	id int,
// 	publicId string,
// 	firstName string,
// 	lastName string,
// 	userName string,
// 	email string,
// 	hashedPassword string,
// 	isVerified bool,
// 	//canSignIn bool,
// 	updated int64) *AuthUser {
// 	return &AuthUser{
// 		Id:              id,
// 		PublicId:        publicId,
// 		FirstName:       firstName,
// 		LastName:        lastName,
// 		Username:        userName,
// 		Email:           email,
// 		HashedPassword:  hashedPassword,
// 		EmailIsVerified: isVerified,
// 		//CanSignIn:      canSignIn,
// 		UpdatedAt: updated}
// }

// Returns the hash of a password. Empty passwords are not
// hashed and return the empty string. Empty passwords are considered
// a special case for passwordless logins.
func HashPassword(password string) string {
	if password == "" {
		return ""
	}

	return string(sys.Must(bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)))
}

// Only to be used for database update events.
func CreateOTP(user *AuthUser) string {
	return HashPassword(strconv.FormatInt(user.UpdatedAt.UnixNano(), 10))

}

func CheckOTPValid(user *AuthUser, otp string) error {
	err := CheckPasswordsMatch(otp, strconv.FormatInt(user.UpdatedAt.UnixNano(), 10))

	if err != nil {
		return errors.New("one time code has expired")
	}

	return nil
}

func Generate6DigitCode() (string, error) {
	const digits = "0123456789"
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = digits[int(b[i])%10]
	}
	return string(b), nil
}
