package auth

import (
	"database/sql"
	"fmt"
	"net/mail"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
)

// See https://echo.labstack.com/docs/cookbook/jwt#login

// partially based on https://betterprogramming.pub/hands-on-with-jwt-in-golang-8c986d1bb4c0

const USERS_SQL string = `SELECT 
	id, public_id, first_name, last_name, username, email, password, email_is_verified, strftime('%s', updated_on) 
	FROM users 
	LIMIT ?2
	OFFSET ?1`

const FIND_USER_BY_ID_SQL string = `SELECT 
	id, public_id, first_name, last_name, username, email, password, email_is_verified, strftime('%s', updated_on) 
	FROM users 
	WHERE users.id = ?1`

const FIND_USER_BY_PUBLIC_ID_SQL string = `SELECT 
	id, public_id, first_name, last_name, username, email, password, email_is_verified, strftime('%s', updated_on) 
	FROM users 
	WHERE users.public_id = ?1`

const FIND_USER_BY_EMAIL_SQL string = `SELECT 
	id, public_id, first_name, last_name, username, email, password, email_is_verified, strftime('%s', updated_on) 
	FROM users 
	WHERE users.email = ?1`

const FIND_USER_BY_USERNAME_SQL string = `SELECT 
	id, public_id, first_name, last_name, username, email, password, email_is_verified, strftime('%s', updated_on) 
	FROM users 
	WHERE users.username = ?1`

const ROLES_SQL string = `SELECT 
	roles.id, roles.public_id, roles.name, roles.description
	FROM roles 
	ORDER BY roles.name`

const USER_PERMISSIONS string = `SELECT DISTINCT 
	permissions.id, permissions.public_id, permissions.name, permissions.description
	FROM users_roles, roles_permissions, permissions 
	WHERE users_roles.user_id = ?1 AND roles_permissions.role_id = users_roles.role_id AND permissions.id = roles_permissions.permission_id 
	ORDER BY permissions.name`

const USER_ROLES string = `SELECT DISTINCT 
	roles.id, roles.public_id, roles.name, roles.description
	FROM users_roles, roles 
	WHERE users_roles.user_id = ?1 AND roles.id = users_roles.role_id 
	ORDER BY roles.name`

const INSERT_USER_SQL = `INSERT INTO users 
	(public_id, username, email, password, first_name, last_name, email_is_verified) 
	VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT DO NOTHING`

const INSERT_USER_ROLE_SQL = "INSERT INTO users_roles (user_id, role_id) VALUES(?1, ?2) ON CONFLICT DO NOTHING"

const SET_EMAIL_IS_VERIFIED_SQL = `UPDATE users SET email_is_verified = 1 WHERE users.public_id = ?`
const SET_PASSWORD_SQL = `UPDATE users SET password = ? WHERE users.public_id = ?`
const SET_USERNAME_SQL = `UPDATE users SET username = ? WHERE users.public_id = ?`
const SET_NAME_SQL = `UPDATE users SET first_name = ?, last_name = ? WHERE users.public_id = ?`
const SET_INFO_SQL = `UPDATE users SET username = ?2, first_name = ?3, last_name = ?4 WHERE users.public_id = ?1`
const SET_EMAIL_SQL = `UPDATE users SET email = ? WHERE users.public_id = ?`

const MIN_PASSWORD_LENGTH int = 8
const MIN_NAME_LENGTH int = 4

type UserDb struct {
	//db *sql.DB
	//setEmailVerifiedStmt *sql.Stmt
	//setPasswordStmt      *sql.Stmt
	//setUsernameStmt      *sql.Stmt
	//setNameStmt  *sql.Stmt
	//setInfoStmt  *sql.Stmt
	//setEmailStmt *sql.Stmt
	file string
}

var PASSWORD_REGEX *regexp.Regexp
var USERNAME_REGEX *regexp.Regexp
var EMAIL_REGEX *regexp.Regexp
var NAME_REGEX *regexp.Regexp

func init() {
	PASSWORD_REGEX = regexp.MustCompile(`^[A-Za-z\d\@\$\!\%\*\#\?\&\.\~\^\-]*$`)
	EMAIL_REGEX = regexp.MustCompile(`^\w+([\.\_\-]\w+)*@\w+([\.\_\-]\w+)*\.[a-zA-Z]{2,}$`)
	USERNAME_REGEX = regexp.MustCompile(`^[\w\-\.]+$`)
	NAME_REGEX = regexp.MustCompile(`^[\w\- ]+$`)
}

func NewUserDB(file string) *UserDb {

	return &UserDb{file: file}
}

// func (userdb *UserDb) Close() {
// 	if userdb.db != nil {
// 		userdb.db.Close()
// 	}
// }

func (userdb *UserDb) NumUsers() (uint, error) {
	db, err := sql.Open("sqlite3", userdb.file) //not clear on what is needed for the user and password

	if err != nil {
		return 0, err
	}

	defer db.Close()

	var n uint

	err = db.QueryRow("SELECT COUNT(ID) FROM users").Scan(&n)

	if err != nil {
		return 0, err
	}

	return n, nil
}

func (userdb *UserDb) Users(offset int, records int) ([]*AuthUser, error) {
	db, err := sql.Open("sqlite3", userdb.file) //not clear on what is needed for the user and password

	if err != nil {
		return nil, err
	}

	defer db.Close()

	rows, err := db.Query(USERS_SQL, offset, records)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var authUsers []*AuthUser

	for rows.Next() {
		var authUser AuthUser
		err := rows.Scan(&authUser.Id,
			&authUser.PublicId,
			&authUser.FirstName,
			&authUser.LastName,
			&authUser.Username,
			&authUser.Email,
			&authUser.HashedPassword,
			&authUser.EmailIsVerified,
			&authUser.Updated)

		if err != nil {
			return nil, err
		}

		userdb.updateUserRoles(&authUser)

		authUsers = append(authUsers, &authUser)
	}

	return authUsers, nil
}

func (userdb *UserDb) FindUserByEmail(email *mail.Address, db *sql.DB) (*AuthUser, error) {
	// e, err := mail.ParseAddress(email)

	// if err != nil {
	// 	return nil, err
	// }

	if db == nil {
		db, err := sql.Open("sqlite3", userdb.file) //not clear on what is needed for the user and password

		if err != nil {
			return nil, err
		}

		defer db.Close()
	}

	var authUser AuthUser
	err := db.QueryRow(FIND_USER_BY_EMAIL_SQL, email.Address).Scan(&authUser.Id,
		&authUser.PublicId,
		&authUser.FirstName,
		&authUser.LastName,
		&authUser.Username,
		&authUser.Email,
		&authUser.HashedPassword,
		&authUser.EmailIsVerified,
		&authUser.Updated)

	if err != nil {
		return nil, err
	}

	err = userdb.updateUserRoles(&authUser)

	if err != nil {
		return nil, err
	}

	return &authUser, nil
}

func (userdb *UserDb) FindUserByUsername(username string) (*AuthUser, error) {
	db, err := sql.Open("sqlite3", userdb.file) //not clear on what is needed for the user and password

	if err != nil {
		return nil, err
	}

	defer db.Close()

	if strings.Contains(username, "@") {
		email, err := mail.ParseAddress(username)

		if err != nil {
			return nil, err
		}

		return userdb.FindUserByEmail(email, db)
	}

	err = CheckUsername(username)

	if err != nil {
		return nil, err
	}

	log.Debug().Msgf("did we call %s", username)

	var authUser AuthUser
	err = db.QueryRow(FIND_USER_BY_USERNAME_SQL, username).Scan(&authUser.Id,
		&authUser.PublicId,
		&authUser.FirstName,
		&authUser.LastName,
		&authUser.Username,
		&authUser.Email,
		&authUser.HashedPassword,
		&authUser.EmailIsVerified,
		&authUser.Updated)

	if err != nil {
		return nil, err
	}

	err = userdb.updateUserRoles(&authUser)

	if err != nil {
		return nil, err
	}

	return &authUser, nil
}

func (userdb *UserDb) FindUserById(id int) (*AuthUser, error) {
	db, err := sql.Open("sqlite3", userdb.file) //not clear on what is needed for the user and password

	if err != nil {
		return nil, err
	}

	defer db.Close()

	var authUser AuthUser

	err = db.QueryRow(FIND_USER_BY_ID_SQL, id).Scan(&authUser.Id,
		&authUser.PublicId,
		&authUser.FirstName,
		&authUser.LastName,
		&authUser.Username,
		&authUser.Email,
		&authUser.HashedPassword,
		&authUser.EmailIsVerified,
		&authUser.Updated)

	if err != nil {
		return nil, err
	}

	err = userdb.updateUserRoles(&authUser)

	if err != nil {
		return nil, err
	}

	return &authUser, nil
}

func (userdb *UserDb) FindUserByPublicId(public_id string) (*AuthUser, error) {
	db, err := sql.Open("sqlite3", userdb.file) //not clear on what is needed for the user and password

	if err != nil {
		return nil, err
	}

	defer db.Close()

	var authUser AuthUser

	err = db.QueryRow(FIND_USER_BY_PUBLIC_ID_SQL, public_id).Scan(&authUser.Id,
		&authUser.PublicId,
		&authUser.FirstName,
		&authUser.LastName,
		&authUser.Username,
		&authUser.Email,
		&authUser.HashedPassword,
		&authUser.EmailIsVerified,
		&authUser.Updated)

	if err != nil {
		return nil, err
	}

	err = userdb.updateUserRoles(&authUser)

	if err != nil {
		return nil, err
	}

	return &authUser, nil
}

func (userdb *UserDb) updateUserRoles(authUser *AuthUser) error {

	roles, err := userdb.RoleList(authUser)

	if err != nil {
		return err //fmt.Errorf("there was an error with the database query")
	}

	authUser.Roles = roles

	return nil
}

func (userdb *UserDb) RoleList(user *AuthUser) ([]string, error) {

	roles, err := userdb.UserRoles(user)

	if err != nil {
		return nil, err
	}

	ret := make([]string, len(roles))

	for ri, role := range roles {
		ret[ri] = role.Name
	}

	return ret, nil

}

func (userdb *UserDb) PermissionList(user *AuthUser) ([]string, error) {

	permissions, err := userdb.UserPermissions(user)

	if err != nil {
		return nil, err
	}

	ret := make([]string, len(permissions))

	for pi, permission := range permissions {
		ret[pi] = permission.Name
	}

	return ret, nil

}

func (userdb *UserDb) NewConn() (*sql.DB, error) {
	return sql.Open("sqlite3", userdb.file)

}

// func (userdb *UserDb) Query(query string, args ...any) (*sql.Rows, error) {
// 	return userdb.db.Query(query, args...)
// }

// func (userdb *UserDb) QueryRow(query string, args ...any) *sql.Row {
// 	db, err := sql.Open("sqlite3", userdb.file) //not clear on what is needed for the user and password

// 	if err != nil {
// 		return nil, err
// 	}

// 	defer db.Close()
// 	return userdb.db.QueryRow(query, args...)
// }

func (userdb *UserDb) Roles() ([]*Role, error) {
	db, err := userdb.NewConn()

	if err != nil {
		return nil, err
	}

	defer db.Close()

	rows, err := db.Query(ROLES_SQL)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var roles []*Role

	for rows.Next() {
		var role Role
		err := rows.Scan(&role.Id,
			&role.PublicId,
			&role.Name,
			&role.Description)

		if err != nil {
			return nil, err
		}
		roles = append(roles, &role)
	}

	return roles, nil
}

func (userdb *UserDb) Role(name string) (*Role, error) {
	db, err := userdb.NewConn()

	if err != nil {
		return nil, err
	}

	defer db.Close()

	var role Role
	err = db.QueryRow("SELECT id, public_id, name, description FROM roles WHERE roles.name = ?", name).Scan(&role.Id,
		&role.PublicId,
		&role.Name,
		&role.Description)

	if err != nil {
		return nil, err
	}

	return &role, err
}

func (userdb *UserDb) UserRoles(user *AuthUser) ([]*Role, error) {

	db, err := userdb.NewConn() //not clear on what is needed for the user and password

	if err != nil {
		return nil, err
	}

	defer db.Close()

	rows, err := db.Query(USER_ROLES, user.Id)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	roles := make([]*Role, 0, 10)

	for rows.Next() {
		var role Role
		err := rows.Scan(&role.Id, &role.PublicId, &role.Name, &role.Description)

		if err != nil {
			return nil, err
		}
		roles = append(roles, &role)
	}

	return roles, nil
}

func (userdb *UserDb) UserPermissions(user *AuthUser) ([]*Permission, error) {

	db, err := userdb.NewConn() //not clear on what is needed for the user and password

	if err != nil {
		return nil, err
	}

	defer db.Close()

	rows, err := db.Query(USER_PERMISSIONS, user.Id)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	permissions := make([]*Permission, 0, 10)

	for rows.Next() {
		var permission Permission
		err := rows.Scan(&permission.Id, &permission.PublicId, &permission.Name, &permission.Description)

		if err != nil {
			return nil, err
		}
		permissions = append(permissions, &permission)
	}

	return permissions, nil
}

func (userdb *UserDb) SetIsVerified(userId string) error {

	db, err := userdb.NewConn() //not clear on what is needed for the user and password

	if err != nil {
		return err
	}

	defer db.Close()

	_, err = db.Exec(SET_EMAIL_IS_VERIFIED_SQL, userId)

	if err != nil {
		return err
	}

	// _, err = userdb.setOtpStmt.Exec("", userId)

	// if err != nil {
	// 	return false
	// }

	return nil
}

func (userdb *UserDb) SetPassword(public_id string, password string) error {
	err := CheckPassword(password)

	if err != nil {
		return err
	}

	hash := HashPassword(password)

	db, err := userdb.NewConn() //not clear on what is needed for the user and password

	if err != nil {
		return err
	}

	defer db.Close()

	_, err = db.Exec(SET_PASSWORD_SQL, hash, public_id)

	if err != nil {
		return fmt.Errorf("could not update password")
	}

	return err
}

func (userdb *UserDb) SetUsername(public_id string, username string) error {

	err := CheckUsername(username)

	if err != nil {
		return err
	}

	db, err := userdb.NewConn() //not clear on what is needed for the user and password

	if err != nil {
		return err
	}

	defer db.Close()

	_, err = db.Exec(SET_USERNAME_SQL, username, public_id)

	if err != nil {
		return fmt.Errorf("could not update username")
	}

	return err
}

func (userdb *UserDb) SetName(public_id string, firstName string, lastName string) error {
	err := CheckName(firstName)

	if err != nil {
		return err
	}

	err = CheckName(lastName)

	if err != nil {
		return err
	}

	db, err := userdb.NewConn() //not clear on what is needed for the user and password

	if err != nil {
		return err
	}

	defer db.Close()

	_, err = db.Exec(SET_NAME_SQL, firstName, lastName, public_id)

	if err != nil {
		return fmt.Errorf("could not update name")
	}

	return err
}

func (userdb *UserDb) SetUserInfo(publicId string, username string, firstName string, lastName string) error {

	err := CheckUsername(username)

	if err != nil {
		return err
	}

	err = CheckName(firstName)

	if err != nil {
		return err
	}

	err = CheckName(lastName)

	if err != nil {
		return err
	}

	db, err := userdb.NewConn() //not clear on what is needed for the user and password

	if err != nil {
		return err
	}

	defer db.Close()

	_, err = db.Exec(SET_INFO_SQL, publicId, username, firstName, lastName)

	log.Debug().Msgf("%s ", err)

	if err != nil {
		return fmt.Errorf("could not update user info")
	}

	return err
}

func (userdb *UserDb) SetEmail(publicId string, email string) error {
	address, err := mail.ParseAddress(email)

	if err != nil {
		return err
	}

	return userdb.SetEmailAddress(publicId, address)
}

func (userdb *UserDb) SetEmailAddress(publicId string, address *mail.Address) error {
	db, err := userdb.NewConn()

	if err != nil {
		return err
	}

	defer db.Close()

	_, err = db.Exec(SET_EMAIL_SQL, address.Address, publicId)

	if err != nil {
		return fmt.Errorf("could not update email address")
	}

	return err
}

func (userdb *UserDb) AddRoleToUser(user *AuthUser, roleName string) error {
	role, err := userdb.Role(roleName)

	if err != nil {
		return err
	}

	db, err := userdb.NewConn()

	if err != nil {
		return err
	}

	defer db.Close()

	_, err = db.Exec(INSERT_USER_ROLE_SQL, user.Id, role.Id)

	if err != nil {
		return err
	}

	return nil
}

// func (userdb *UserDb) SetOtp(userId string, otp string) error {
// 	_, err := userdb.setOtpStmt.Exec(otp, userId)

// 	return err
// }

func (userdb *UserDb) CreateUserFromSignup(user *SignupReq) (*AuthUser, error) {
	email, err := mail.ParseAddress(user.Email)

	if err != nil {
		return nil, err
	}

	// The default username is email address unless a username is provided
	userName := email.Address

	if user.UserName != "" {
		userName = user.UserName
	}

	// assume email is not verified
	return userdb.CreateUser(userName, email, user.Password, user.FirstName, user.LastName, false)
}

func (userdb *UserDb) CreateUser(userName string,
	email *mail.Address,
	password string,
	firstName string,
	lastName string,
	emailIsVerified bool) (*AuthUser, error) {
	err := CheckPassword(password)

	if err != nil {
		return nil, err
	}

	db, err := userdb.NewConn() //not clear on what is needed for the user and password

	if err != nil {
		return nil, err
	}

	defer db.Close()

	// Check if user exists and if they do, check passwords match.
	// We don't care about errors because errors signify the user
	// doesn't exist so we can continue and make the user
	authUser, err := userdb.FindUserByEmail(email, db)

	// try to create user if user does not exist
	if err != nil {
		// Create a public_id for the user id
		public_id := NanoId()

		hash := ""

		// empty passwords indicate passwordless
		if password != "" {
			hash = HashPassword(password)
		}

		// verified := 0

		// if emailIsVerified {
		// 	verified = 1
		// }

		//log.Debug().Msgf("%s %s", user.FirstName, user.Email)
		//public_id, username, email, password, first_name, last_name

		_, err = db.Exec(INSERT_USER_SQL,
			public_id,
			userName,
			email.Address,
			hash,
			firstName,
			lastName,
			emailIsVerified,
		)

		if err != nil {
			return nil, err
		}

		// Call function again to get the user details
		authUser, err = userdb.FindUserByEmail(email, db)

		if err != nil {
			return nil, err
		}
	} else {
		// user already exists so check if verified

		if authUser.EmailIsVerified {
			return nil, fmt.Errorf("user already registered:please sign up with another email address")
		}

		// if user is not verified, update the password since we assume
		// rightful owner of email address will keep trying until verified
		// this is to stop people blocking creation of accounts by just
		// signing up with email addresses they have no intention of
		// verifying
		err := userdb.SetPassword(authUser.PublicId, password)

		if err != nil {
			return nil, fmt.Errorf("user already registered:please sign up with another email address")
		}
	}

	// Give user standard role and ability to login
	userdb.AddRoleToUser(authUser, ROLE_USER)
	userdb.AddRoleToUser(authUser, ROLE_LOGIN)

	// err = userdb.SetOtp(authUser.UserId, otp)

	// if err != nil {
	// 	return nil, fmt.Errorf("could not set otp")
	// }

	return authUser, nil
}

// Make sure password meets requirements
func CheckPassword(password string) error {
	// empty passwords are a special case used to indicate
	// passwordless only login
	if password == "" {
		return nil
	}

	if len(password) < MIN_PASSWORD_LENGTH {
		return fmt.Errorf("password must be at least %d characters", MIN_PASSWORD_LENGTH)
	}

	if !PASSWORD_REGEX.MatchString(password) {
		return fmt.Errorf("invalid password")
	}

	return nil
}

// Make sure password meets requirements
func CheckUsername(username string) error {
	if len(username) < MIN_NAME_LENGTH {
		return fmt.Errorf("username must be at least %d characters", MIN_NAME_LENGTH)
	}

	if !USERNAME_REGEX.MatchString(username) {
		return fmt.Errorf("invalid username")
	}

	return nil
}

// Make sure password meets requirements
func CheckName(name string) error {
	if len(name) < MIN_NAME_LENGTH {
		return fmt.Errorf("name must be at least %d characters", MIN_NAME_LENGTH)
	}

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
