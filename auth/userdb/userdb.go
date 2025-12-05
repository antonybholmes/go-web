package userdb

import (
	"crypto/ed25519"
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
	// UserNotFoundError struct {
	// 	s string
	// }

	// PasswordError struct {
	// 	s string
	// }

	UserDB interface {
		NumUsers() (int, error)

		Users(records int, offset int) ([]*auth.AuthUser, error)

		DeleteUser(publicId string) error

		// find a user by their email address, returns
		// an error if not found
		FindUserByEmail(email *mail.Address) (*auth.AuthUser, error)

		FindUserByUsername(username string) (*auth.AuthUser, error)

		FindUserById(id string) (*auth.AuthUser, error)

		//FindUserByPublicId(publicId string) (*auth.AuthUser, error)

		FindUserByApiKey(key string) (*auth.AuthUser, error)

		//AddGroupsToUser(authUser *auth.AuthUser) error

		//UserRoleList(user *auth.AuthUser) ([]string, error)

		//AddApiKeysToUser(authUser *auth.AuthUser) error

		//AddPublicKeysToUser(authUser *auth.AuthUser, keys []ed25519.PublicKey) error

		UserApiKeys(user *auth.AuthUser) ([]string, error)

		// get the public keys for a user
		UserPublicKeys(user *auth.AuthUser) ([]ed25519.PublicKey, error)

		UserGroups(user *auth.AuthUser) ([]*auth.RBACGroup, error)

		//PermissionList(user *auth.AuthUser) ([]string, error)

		Roles() ([]*auth.RBACRole, error)
		Groups() ([]*auth.RBACGroup, error)

		FindRoleByName(name string) (*auth.RBACRole, error)
		FindGroup(name string) (*auth.RBACGroup, error)

		// Get a list of permissions for a user
		//Permissions(user *auth.AuthUser) ([]*auth.Permission, error)

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

		// set a user's groups
		SetUserGroups(user *auth.AuthUser, groups []string, adminMode bool) error

		// add a group to a user
		AddUserToGroup(user *auth.AuthUser, group *auth.RBACGroup, adminMode bool) error

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
	MinPasswordLength = 8
	MinNameLength     = 3

	EpochDate = "1970-01-01"

	// 1970-01-01 mysql
	EmailNotVerifiedDate time.Duration = 62167219200 //31556995200
)

var (
	PasswordRegex = regexp.MustCompile(`^[A-Za-z\d@\$!%\*#\$&\.\~\^\-]*$`)
	EmailRegex    = regexp.MustCompile(`^\w+([\.\_\-]\w+)*@\w+([\.\_\-]\w+)*\.[a-zA-Z]{2,}$`)
	UsernameRegex = regexp.MustCompile(`^[\w\-\.@]+$`)
	// name can be empty or contain letters, numbers, spaces, dashes, and underscores
	NameRegex = regexp.MustCompile(`^[\w\-\_ ]*$`)
)

// Make sure password meets requirements
func CheckPassword(password string) error {
	// empty passwords are a special case used to indicate
	// passwordless only login
	if password == "" {
		return nil
	}

	if len(password) < MinPasswordLength {
		return auth.NewAccountError(fmt.Sprintf("password must be at least %d characters", MinPasswordLength))
	}

	if !PasswordRegex.MatchString(password) {
		return auth.NewAccountError("invalid password")
	}

	return nil
}

// Make sure password meets requirements
func CheckUsername(username string) error {
	if len(username) < MinNameLength {
		return auth.NewAccountError(fmt.Sprintf("username must be at least %d characters", MinNameLength))
	}

	if !UsernameRegex.MatchString(username) {
		return auth.NewAccountError("invalid username")
	}

	return nil
}

func CheckName(name string) error {
	//if len(name) < MIN_NAME_LENGTH {
	//	return fmt.Errorf("%s must be at least %d characters", name, MIN_NAME_LENGTH)
	//}

	if !NameRegex.MatchString(name) {
		return auth.NewAccountError("invalid name")
	}

	return nil
}
