package userdb

import (
	"fmt"
	"net/mail"
	"regexp"
	"time"

	"github.com/antonybholmes/go-web/auth"
)

// MySQL version

// See https://echo.labstack.com/docs/cookbook/jwt#login

// partially based on https://betterprogramming.pub/hands-on-with-jwt-in-golang-8c986d1bb4c0

//const EMAIL_NOT_VERIFIED_TIME_S = 62167219200

type UserDB interface {
	NumUsers() (uint, error)

	Users(records uint, offset uint) ([]*auth.AuthUser, error)

	DeleteUser(publicId string) error

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

	Permissions(user *auth.AuthUser) ([]*auth.Permission, error)
	SetIsVerified(userId string) error

	SetPassword(user *auth.AuthUser, password string) error

	SetUserInfo(user *auth.AuthUser,
		username string,
		firstName string,
		lastName string,
		adminMode bool) error

	SetEmailAddress(user *auth.AuthUser, address *mail.Address, adminMode bool) error

	SetUserRoles(user *auth.AuthUser, roles []string, adminMode bool) error

	AddRoleToUser(user *auth.AuthUser, roleName string, adminMode bool) error

	CreateApiKeyForUser(user *auth.AuthUser, adminMode bool) error

	CreateUserFromSignup(user *auth.UserBodyReq) (*auth.AuthUser, error)

	CreateUserFromOAuth2(name string, email *mail.Address) (*auth.AuthUser, error)

	CreateUser(userName string,
		email *mail.Address,
		password string,
		firstName string,
		lastName string,
		emailIsVerified bool) (*auth.AuthUser, error)
}

const (
	// mysql version
	// SelectUsersSql string = `SELECT
	// id,
	// public_id,
	// first_name,
	// last_name,
	// username,
	// email,
	// is_locked,
	// password,
	// TO_SECONDS(email_verified_at) as email_verified_at,
	// TO_SECONDS(created_at) as created_at,
	// TO_SECONDS(updated_at) as updated_at
	// FROM users
	// `

	// postgres version
	SelectUsersSql string = `SELECT 
	id, 
	public_id, 
	first_name, 
	last_name, 
	username, 
	email, 
	is_locked, 
	password, 
	FLOOR(EXTRACT(EPOCH FROM email_verified_at)) as email_verified_at, 
	FLOOR(EXTRACT(EPOCH FROM created_at)) as created_at, 
	FLOOR(EXTRACT(EPOCH FROM updated_at)) as updated_at
	FROM users
	`

	UsersSql string = SelectUsersSql + ` ORDER BY first_name, last_name, email LIMIT ? OFFSET ?`

	FindUserByIdSql string = SelectUsersSql + ` WHERE users.id = ?`

	FindUserByPublicIdSql string = SelectUsersSql + ` WHERE users.public_id = ?`

	FindUserByEmailSql string = SelectUsersSql + ` WHERE users.email = ?`

	FindUserByUsernameSql string = SelectUsersSql + ` WHERE users.username = ?`

	FindUserByApiKeySql string = `SELECT 
	id, user_id, api_key
	FROM api_keys 
	WHERE api_key = ?`

	UsersApiKeysSql string = `SELECT 
	id, api_key
	FROM api_keys 
	WHERE user_id = ?
	ORDER BY api_key`

	RolesSql string = `SELECT 
	id, 
	public_id, 
	name, 
	description
	FROM roles 
	ORDER BY roles.name`

	PermissionsSql string = `SELECT DISTINCT 
	permissions.id, 
	permissions.public_id, 
	permissions.name, 
	permissions.description
	FROM users_roles, roles_permissions, permissions 
	WHERE users_roles.user_id = ? AND roles_permissions.role_id = users_roles.role_id AND 
	permissions.id = roles_permissions.permission_id 
	ORDER BY permissions.name`

	UserRolesSql string = `SELECT DISTINCT 
	roles.id, 
	roles.public_id, 
	roles.name, 
	roles.description
	FROM users_roles, roles 
	WHERE users_roles.user_id = ? AND roles.id = users_roles.role_id 
	ORDER BY roles.name`

	InsertUserSql = `INSERT IGNORE INTO users 
	(public_id, username, email, password, first_name, last_name, email_verified_at) 
	VALUES (?, ?, ?, ?, ?, ?, ?)`

	DeleteRolesSql    = "DELETE FROM users_roles WHERE user_id = ?"
	InsertUserRoleSql = "INSERT IGNORE INTO users_roles (user_id, role_id) VALUES(?, ?)"

	InsertApiKeySql = "INSERT IGNORE INTO api_keys (user_id, api_key) VALUES(?, ?)"

	SetEmailVerifiedSql = `UPDATE users SET email_verified_at = now() WHERE users.public_id = ?`
	SetPasswordSql      = `UPDATE users SET password = ? WHERE users.public_id = ?`
	SetUsernameSql      = `UPDATE users SET username = ? WHERE users.public_id = ?`

	//   SET_NAME_SQL = `UPDATE users SET first_name = 1, last_name = 1 WHERE users.public_id = 1`
	SetInfoSql  = `UPDATE users SET username = ?, first_name = ?, last_name = ? WHERE users.public_id = ?`
	SetEmailSql = `UPDATE users SET email = ? WHERE users.public_id = ?`

	DeleteUserSql = `DELETE FROM users WHERE public_id = ?`

	CountUsersSql = `SELECT COUNT(ID) FROM users`

	RoleSql = `SELECT 
	roles.id, 
	roles.public_id, 
	roles.name,
	roles.description 
	FROM roles WHERE roles.name = ?`

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
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}

	if !PASSWORD_REGEX.MatchString(password) {
		return fmt.Errorf("invalid password")
	}

	return nil
}

// Make sure password meets requirements
func CheckUsername(username string) error {
	if len(username) < MinNameLength {
		return fmt.Errorf("username must be at least %d characters", MinNameLength)
	}

	if !USERNAME_REGEX.MatchString(username) {
		return fmt.Errorf("invalid username")
	}

	return nil
}

func CheckName(name string) error {
	//if len(name) < MIN_NAME_LENGTH {
	//	return fmt.Errorf("%s must be at least %d characters", name, MIN_NAME_LENGTH)
	//}

	if !NAME_REGEX.MatchString(name) {
		return fmt.Errorf("invalid name")
	}

	return nil
}

// func CheckEmailIsWellFormed(email string) (*mail.Address, error) {
// 	log.Debug().Msgf("validate %s", email)
// 	if !EMAIL_REGEX.MatchString(email) {
// 		return nil, fmt.Errorf("invalid email address")
// 	}

// 	address, err := mail.ParseAddress(email)

// 	if err != nil {
// 		return nil, fmt.Errorf("could not parse email")
// 	}

// 	return address, nil
// }
