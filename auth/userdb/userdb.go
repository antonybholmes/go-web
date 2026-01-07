package userdb

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"
	"unicode"

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

		//userApiKeys(user *auth.AuthUser) ([]string, error)

		// get the public keys for a user
		//UserPublicKeys(user *auth.AuthUser) ([]ed25519.PublicKey, error)

		//UserGroups(user *auth.AuthUser) ([]*auth.RBACGroup, error)

		//PermissionList(user *auth.AuthUser) ([]string, error)

		Roles() ([]*auth.RBACRole, error)
		Groups() ([]*auth.RBACGroup, error)

		FindRoleByName(name string) (*auth.RBACRole, error)
		FindGroupById(id string) (*auth.RBACGroup, error)
		FindGroupByName(name string) (*auth.RBACGroup, error)

		// Get a list of permissions for a user
		//Permissions(user *auth.AuthUser) ([]*auth.Permission, error)

		// Mark a user's email as verified
		SetEmailIsVerified(user *auth.AuthUser) (*time.Time, error)

		SetUsername(user *auth.AuthUser, username string, adminMode bool) (string, error)

		// change a user's password
		SetPassword(user *auth.AuthUser, password string, adminMode bool) (string, error)

		// update user info
		SetUserInfo(user *auth.AuthUser,
			username string,
			name string,
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
		CreateUserFromOAuth2(email *mail.Address, name string, authProvider string) (*auth.AuthUser, error)

		// create a complete new user, this is more for
		// traditional logins, generally CreateUserFromOAuth2 is preferred
		CreateOrUpdateUser(email *mail.Address,
			userName string,
			password string,
			name string,
			emailIsVerified bool,
			authProvider string) (*auth.AuthUser, error)

		CreateUser(email *mail.Address,
			userName string,
			password string,
			name string,
			emailIsVerified bool,
			authProvider string) (*auth.AuthUser, error)
	}
)

const (
	MinPasswordLength = 8
	MaxPasswordLength = 256
	MinNameLength     = 3

	EpochDate = "1970-01-01"

	// allowed special characters in passwords
	allowedSpecial = "@$!%*#&.^~-"

	// 1970-01-01 mysql
	//EmailNotVerifiedDate time.Duration = 62167219200 //31556995200

)

var (
	//PasswordRegex = regexp.MustCompile(`^[A-Za-z\d@\$!%\*#\$&\.\~\^\-]*$`)
	EmailRegex    = regexp.MustCompile(`/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/`) //^\w+([\.\_\-]\w+)*@\w+([\.\_\-]\w+)*\.[a-zA-Z]{2,}$`)
	UsernameRegex = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	// name can be empty or contain letters, numbers, spaces, dashes, and underscores
	NameRegex = regexp.MustCompile(`^[A-Za-z]+(?:[\s'-][A-Za-z]+)*$`) //^[\w\- ]*$`)

	//EmailNotVerifiedDate time.Time = time.Unix(0, 0).UTC() // 1970-01-01 00:00:00

	// allowedSpecial = map[rune]struct{}{
	// 	'@': {}, '$': {}, '!': {}, '%': {}, '*': {}, '#': {}, '&': {}, '.': {}, '^': {}, '~': {}, '-': {},
	// }
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

	// do not allow overly long passwords, but 256 should be plenty and
	// this is mainly to prevent abuse and is software imposed so can
	// be raised if needed since the database doen't limit it
	if len(password) > MaxPasswordLength {
		return auth.NewAccountError(fmt.Sprintf("password must be at most %d characters", MaxPasswordLength))
	}

	// if !PasswordRegex.MatchString(password) {
	// 	return auth.NewAccountError("invalid password")
	// }

	var hasUpper, hasLower, hasDigit, hasSpecial bool

	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case strings.ContainsRune(allowedSpecial, ch):
			hasSpecial = true
		default:
			// Invalid character not allowed
			return auth.NewAccountError("invalid chars in password")
		}
	}

	if !hasUpper {
		return auth.NewAccountError("password must contain at least one uppercase letter")
	}

	if !hasLower {
		return auth.NewAccountError("password must contain at least one lowercase letter")
	}

	if !hasDigit {
		return auth.NewAccountError("password must contain at least one digit")
	}

	if !hasSpecial {
		return auth.NewAccountError("password must contain at least one special character from " + allowedSpecial)
	}

	return nil
}

// Make sure password meets requirements
func CheckUsername(username string) error {
	if len(username) < MinNameLength {
		return auth.NewAccountError(fmt.Sprintf("username %s must be at least %d characters", username, MinNameLength))
	}

	// if either a valid username or email, it's ok
	if UsernameRegex.MatchString(username) || EmailRegex.MatchString(username) {
		return nil
	}

	return auth.NewAccountError(username + " is an invalid username")
}

// Make sure name meets requirements which is either a personal name or email address
// There is no requirement for a name to be provided and no minimum length
// but if one is provided it must be well formed. A name containing @ will be
// treated as an email address so it must match an email format otherwise. Personal
// names are looser, but must only contain letters, spaces, dashes or apostrophes
func CheckName(name string) error {
	if len(name) == 0 {
		return nil
	}

	// if either a valid name or email, it's ok
	if NameRegex.MatchString(name) || EmailRegex.MatchString(name) {
		return nil
	}

	// if not valid email address throw error
	// if !isEmail {
	// 	return auth.NewAccountError(fmt.Sprintf("name %s is not a valid email address", name))
	// }

	// asssume it's meant to be a personal name
	return auth.NewAccountError(name + " is not a valid name")
}
