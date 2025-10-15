package userdb

import (
	"fmt"
	"net/mail"
	"regexp"
	"time"

	"github.com/antonybholmes/go-web/auth"
)

// See https://echo.labstack.com/docs/cookbook/jwt#login

// partially based on https://betterprogramming.pub/hands-on-with-jwt-in-golang-8c986d1bb4c0

//const EMAIL_NOT_VERIFIED_TIME_S = 62167219200

type (
	UserNotFoundError struct {
		s string
	}

	PasswordError struct {
		s string
	}

	AccountError struct {
		s string
	}

	UserDB interface {
		NumUsers() (uint, error)

		Users(records uint, offset uint) ([]*auth.AuthUser, error)

		DeleteUser(publicId string) error

		// find a user by their email address, returns
		// an error if not found
		FindUserByEmail(email *mail.Address) (*auth.AuthUser, error)

		FindUserByUsername(username string) (*auth.AuthUser, error)

		FindUserById(id uint) (*auth.AuthUser, error)

		FindUserByPublicId(publicId string) (*auth.AuthUser, error)

		FindUserByApiKey(key string) (*auth.AuthUser, error)

		AddRolesToUser(authUser *auth.AuthUser) error

		UserRoleList(user *auth.AuthUser) ([]string, error)

		AddApiKeysToUser(authUser *auth.AuthUser) error

		UserApiKeys(user *auth.AuthUser) ([]string, error)
		UserRoles(user *auth.AuthUser) ([]*auth.Role, error)

		PermissionList(user *auth.AuthUser) ([]string, error)

		Roles() ([]*auth.Role, error)

		FindRoleByName(name string) (*auth.Role, error)

		// Get a list of permissions for a user
		Permissions(user *auth.AuthUser) ([]*auth.Permission, error)

		// Mark a user's email as verified
		SetIsVerified(userId string) error

		// change a user's password
		SetPassword(user *auth.AuthUser, password string) error

		// update user info
		SetUserInfo(user *auth.AuthUser,
			username string,
			firstName string,
			lastName string,
			adminMode bool) error

		// change a user's email address
		SetEmailAddress(user *auth.AuthUser, address *mail.Address, adminMode bool) error

		// set a user's roles
		SetUserRoles(user *auth.AuthUser, roles []string, adminMode bool) error

		// add a role to a user
		AddRoleToUser(user *auth.AuthUser, roleName string, adminMode bool) error

		// create a new api key for a user, adminMode allows creating keys for other users
		CreateApiKeyForUser(user *auth.AuthUser, adminMode bool) error

		CreateUserFromSignup(user *auth.UserBodyReq) (*auth.AuthUser, error)

		// assumes email is verified by OAuth2 provider so will auto
		// create an account if one doesn't exist for the email address
		CreateUserFromOAuth2(name string, email *mail.Address) (*auth.AuthUser, error)

		// create a complete new user, this is more for
		// traditional logins, generally CreateUserFromOAuth2 is preferred
		CreateUser(userName string,
			email *mail.Address,
			password string,
			firstName string,
			lastName string,
			emailIsVerified bool) (*auth.AuthUser, error)
	}
)

const (
	MinPasswordLength int = 8
	MinNameLength     int = 3

	EpochDate = "1970-01-01"

	// 1970-01-01 mysql
	EmailNotVerifiedDate time.Duration = 62167219200 //31556995200
)

var (
	PASSWORD_REGEX = regexp.MustCompile(`^[A-Za-z\d@\$!%\*#\$&\.\~\^\-]*$`)
	EMAIL_REGEX    = regexp.MustCompile(`^\w+([\.\_\-]\w+)*@\w+([\.\_\-]\w+)*\.[a-zA-Z]{2,}$`)
	USERNAME_REGEX = regexp.MustCompile(`^[\w\-\.@]+$`)
	// name can be empty or contain letters, numbers, spaces, dashes, and underscores
	NAME_REGEX = regexp.MustCompile(`^[\w\-\_ ]*$`)
)

// Make sure password meets requirements
func CheckPassword(password string) error {
	// empty passwords are a special case used to indicate
	// passwordless only login
	if password == "" {
		return nil
	}

	if len(password) < MinPasswordLength {
		return NewPasswordError(fmt.Sprintf("password must be at least %d characters", MinPasswordLength))
	}

	if !PASSWORD_REGEX.MatchString(password) {
		return NewPasswordError("invalid password")
	}

	return nil
}

// Make sure password meets requirements
func CheckUsername(username string) error {
	if len(username) < MinNameLength {
		return NewAccountError(fmt.Sprintf("username must be at least %d characters", MinNameLength))
	}

	if !USERNAME_REGEX.MatchString(username) {
		return NewAccountError("invalid username")
	}

	return nil
}

func CheckName(name string) error {
	//if len(name) < MIN_NAME_LENGTH {
	//	return fmt.Errorf("%s must be at least %d characters", name, MIN_NAME_LENGTH)
	//}

	if !NAME_REGEX.MatchString(name) {
		return NewAccountError("invalid name")
	}

	return nil
}

//
// errors
//

func NewUserNotFoundError(s string) *UserNotFoundError {
	return &UserNotFoundError{s}
}

func (e *UserNotFoundError) Error() string {
	return fmt.Sprintf("user not found: %s", e.s)
}

func NewPasswordError(s string) *PasswordError {
	return &PasswordError{s}
}

func (e *PasswordError) Error() string {
	return fmt.Sprintf("password error: %s", e.s)
}

func NewAccountError(s string) *AccountError {
	return &AccountError{s}
}

func (e *AccountError) Error() string {
	return fmt.Sprintf("account info error: %s", e.s)
}
