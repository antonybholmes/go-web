package auth

import (
	"database/sql"
	"fmt"
	"net/mail"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/antonybholmes/go-sys"
	"github.com/go-sql-driver/mysql"
	"github.com/rs/zerolog/log"
)

// MySQL version

// See https://echo.labstack.com/docs/cookbook/jwt#login

// partially based on https://betterprogramming.pub/hands-on-with-jwt-in-golang-8c986d1bb4c0

//const EMAIL_NOT_VERIFIED_TIME_S = 62167219200

const SELECT_USERS_SQL string = `SELECT 
	id, 
	public_id, 
	first_name, 
	last_name, 
	username, 
	email, 
	is_locked, 
	password, 
	TO_SECONDS(email_verified_at) as email_verified_at, 
	TO_SECONDS(created_at) as created_at, 
	TO_SECONDS(updated_at) as updated_at
	FROM users`

const USERS_SQL string = SELECT_USERS_SQL + ` ORDER BY first_name, last_name, email LIMIT ? OFFSET ?`

const FIND_USER_BY_ID_SQL string = SELECT_USERS_SQL + ` WHERE users.id = ?`

const FIND_USER_BY_PUBLIC_ID_SQL string = SELECT_USERS_SQL + ` WHERE users.public_id = ?`

const FIND_USER_BY_EMAIL_SQL string = SELECT_USERS_SQL + ` WHERE users.email = ?`

const FIND_USER_BY_USERNAME_SQL string = SELECT_USERS_SQL + ` WHERE users.username = ?`

const FIND_USER_BY_API_KEY_SQL string = `SELECT 
	id, user_id, api_key
	FROM api_keys 
	WHERE api_key = ?`

const USER_API_KEYS_SQL string = `SELECT 
	id, api_key
	FROM api_keys 
	WHERE user_id = ?
	ORDER BY api_key`

const ROLES_SQL string = `SELECT 
	roles.id, roles.public_id, roles.name, roles.description
	FROM roles 
	ORDER BY roles.name`

const permissions_SQL string = `SELECT DISTINCT 
	permissions.id, permissions.public_id, permissions.name, permissions.description
	FROM users_roles, roles_permissions, permissions 
	WHERE users_roles.user_id = ? AND roles_permissions.role_id = users_roles.role_id AND 
	permissions.id = roles_permissions.permission_id 
	ORDER BY permissions.name`

const roles_SQL string = `SELECT DISTINCT 
	roles.id, roles.public_id, roles.name, roles.description
	FROM users_roles, roles 
	WHERE users_roles.user_id = ? AND roles.id = users_roles.role_id 
	ORDER BY roles.name`

const INSERT_USER_SQL = `INSERT IGNORE INTO users 
	(public_id, username, email, password, first_name, last_name, email_verified_at) 
	VALUES (?, ?, ?, ?, ?, ?, ?)`

const DELETE_roles_SQL = "DELETE FROM users_roles WHERE user_id = ?"
const INSERT_USER_ROLE_SQL = "INSERT IGNORE INTO users_roles (user_id, role_id) VALUES(?, ?)"

const INSERT_APK_KEY_SQL = "INSERT IGNORE INTO api_keys (user_id, api_key) VALUES(?, ?)"

const SET_EMAIL_IS_VERIFIED_SQL = `UPDATE users SET email_verified_at = now() WHERE users.public_id = ?`
const SET_PASSWORD_SQL = `UPDATE users SET password = ? WHERE users.public_id = ?`
const SET_USERNAME_SQL = `UPDATE users SET username = ? WHERE users.public_id = ?`

// const SET_NAME_SQL = `UPDATE users SET first_name = 1, last_name = 1 WHERE users.public_id = 1`
const SET_INFO_SQL = `UPDATE users SET username = ?, first_name = ?, last_name = ? WHERE users.public_id = ?`
const SET_EMAIL_SQL = `UPDATE users SET email = ? WHERE users.public_id = ?`

const DELETE_USER_SQL = `DELETE FROM users WHERE public_id = ?`

const COUNT_USERS_SQL = `SELECT COUNT(ID) FROM users`

const ROLE_SQL = `SELECT 
	roles.id, 
	roles.public_id, 
	roles.name,
	roles.description 
	FROM roles WHERE roles.name = ?`

const MIN_PASSWORD_LENGTH int = 8
const MIN_NAME_LENGTH int = 4

const EPOCH_DATE = "1970-01-01"

// 1970-01-01 mysql
const EMAIL_NOT_VERIFIED_TIME_S time.Duration = 62167219200 //31556995200

type UserDb struct {
	db *sql.DB
	//ctx context.Context
	//setEmailVerifiedStmt *sql.Stmt
	//setPasswordStmt      *sql.Stmt
	//setUsernameStmt      *sql.Stmt
	//setNameStmt  *sql.Stmt

	//setEmailStmt *sql.Stmt
	//file string
	//prepMap map[string]*sql.Stmt
	// setInfoStmt            *sql.Stmt
	// setEmailStmt           *sql.Stmt
	// findUserByIdStmt       *sql.Stmt
	// findUserByPublicIdStmt *sql.Stmt
	// findUserByEmailStmt    *sql.Stmt
	// findUserByUsernameStmt *sql.Stmt
	// usersStmt              *sql.Stmt
	// userRolesStmt          *sql.Stmt
	// insertUserStmt         *sql.Stmt
	// insertUserRoleStmt     *sql.Stmt
	// rolesStmt              *sql.Stmt
	// roleStmt               *sql.Stmt
	// deleteUserStmt         *sql.Stmt
}

func NewUserDB() *UserDb {
	//db := sys.Must(sql.Open("sqlite3", file))
	cfg := mysql.Config{
		User:                 os.Getenv("MYSQL_USER"),
		Passwd:               os.Getenv("MYSQL_PASSWORD"),
		Net:                  "tcp",
		Addr:                 os.Getenv("MYSQL_ADDR"),
		DBName:               os.Getenv("MYSQL_DATABASE"),
		AllowNativePasswords: true,
	}

	db := sys.Must(sql.Open("mysql", cfg.FormatDSN()))

	return &UserDb{
		db: db,
		//ctx: ctx,
		// findUserByPublicIdStmt: sys.Must(db.Prepare(FIND_USER_BY_PUBLIC_ID_SQL)),
		// findUserByEmailStmt:    sys.Must(db.Prepare(FIND_USER_BY_EMAIL_SQL)),
		// findUserByUsernameStmt: sys.Must(db.Prepare(FIND_USER_BY_USERNAME_SQL)),
		// setInfoStmt:            sys.Must(db.Prepare(SET_INFO_SQL)),
		// setEmailStmt:           sys.Must(db.Prepare(SET_EMAIL_SQL)),
		// usersStmt:              sys.Must(db.Prepare(USERS_SQL)),
		// userRolesStmt:          sys.Must(db.Prepare(roles_SQL)),
		// insertUserStmt:         sys.Must(db.Prepare(INSERT_USER_SQL)),
		// insertUserRoleStmt:     sys.Must(db.Prepare(INSERT_USER_ROLE_SQL)),
		// rolesStmt:              sys.Must(db.Prepare(ROLES_SQL)),
		// roleStmt:               sys.Must(db.Prepare(ROLE_SQL)),
		// deleteUserStmt:         sys.Must(db.Prepare(DELETE_USER_SQL))
	}
}

func (userdb *UserDb) Db() *sql.DB {
	return userdb.db
}

// func (userdb *UserDb) PrepStmt(sql string) *sql.Stmt {
// 	stmt, ok := userdb.prepMap[sql]

// 	if ok {
// 		log.Debug().Msgf("cached stmt %s", sql)
// 		return stmt
// 	}

// 	stmt = sys.Must(userdb.db.Prepare(sql))
// 	userdb.prepMap[sql] = stmt

// 	return stmt
// }

// func (userdb *UserDb) NewConn() (*sql.DB, error) {
// 	return sql.Open("sqlite3", userdb.file)
// }

// // If db is initialized, return it, otherwise create a new
// // connection and return it
// func (userdb *UserDb) AutoConn(db *sql.DB) (*sql.DB, error) {
// 	if db != nil {
// 		return db, nil
// 	}

// 	db, err := userdb.NewConn() //not clear on what is needed for the user and password

// 	if err != nil {
// 		return nil, err
// 	}

// 	//defer db.Close()

// 	return db, nil
// }

var PASSWORD_REGEX *regexp.Regexp
var USERNAME_REGEX *regexp.Regexp
var EMAIL_REGEX *regexp.Regexp
var NAME_REGEX *regexp.Regexp

func init() {
	PASSWORD_REGEX = regexp.MustCompile(`^[A-Za-z\d\@\$\!\%\*\#\$\&\.\~\^\-]*$`)
	EMAIL_REGEX = regexp.MustCompile(`^\w+([\.\_\-]\w+)*@\w+([\.\_\-]\w+)*\.[a-zA-Z]{2,}$`)
	USERNAME_REGEX = regexp.MustCompile(`^[\w\-\.]+$`)
	NAME_REGEX = regexp.MustCompile(`^[\w\- ]+$`)
}

// func (userdb *UserDb) Close() {
// 	if userdb.db != nil {
// 		userdb.db.Close()
// 	}
// }

func (userdb *UserDb) NumUsers() (uint, error) {

	var n uint

	err := userdb.db.QueryRow(COUNT_USERS_SQL).Scan(&n)

	if err != nil {
		return 0, err
	}

	return n, nil
}

func (userdb *UserDb) Users(records uint, offset uint) ([]*AuthUser, error) {
	//log.Debug().Msgf("users %d %d", records, offset)

	rows, err := userdb.db.Query(USERS_SQL, records, offset)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	authUsers := make([]*AuthUser, 0, records)

	//var createdAt time.Duration
	//var updatedAt time.Duration
	//var emailVerifiedAt int64

	for rows.Next() {
		var authUser AuthUser
		err := rows.Scan(&authUser.Id,
			&authUser.PublicId,
			&authUser.FirstName,
			&authUser.LastName,
			&authUser.Username,
			&authUser.Email,
			&authUser.IsLocked,
			&authUser.HashedPassword,
			&authUser.EmailVerifiedAt,
			&authUser.CreatedAt,
			&authUser.UpdatedAt)

		if err != nil {
			log.Debug().Msgf("users err %s", err)
			return nil, err
		}

		//authUser.EmailVerifiedAt = time.Duration(emailVerifiedAt)
		//authUser.UpdatedAt = time.Duration(updatedAt)

		log.Debug().Msgf("this user err %v", authUser)

		err = userdb.AddRolesToUser(&authUser)

		if err != nil {
			return nil, err
		}

		authUsers = append(authUsers, &authUser)
	}

	return authUsers, nil
}

func (userdb *UserDb) DeleteUser(publicId string) error {

	authUser, err := userdb.FindUserByPublicId(publicId)

	if err != nil {
		return err
	}

	roles, err := userdb.UserRoleList(authUser)

	if err != nil {
		return err
	}

	claim := MakeClaim(roles)

	if strings.Contains(claim, ROLE_SUPER) {
		return fmt.Errorf("cannot delete superuser account")
	}

	_, err = userdb.db.Exec(DELETE_USER_SQL, publicId)

	if err != nil {
		return err
	}

	return nil
}

func (userdb *UserDb) FindUserByEmail(email *mail.Address) (*AuthUser, error) {
	return userdb.findUser(userdb.db.QueryRow(FIND_USER_BY_EMAIL_SQL, email.Address))
}

func (userdb *UserDb) FindUserByUsername(username string) (*AuthUser, error) {

	if strings.Contains(username, "@") {
		email, err := mail.ParseAddress(username)

		if err != nil {
			return nil, err
		}

		return userdb.FindUserByEmail(email)
	}

	err := CheckUsername(username)

	if err != nil {
		return nil, err
	}

	return userdb.findUser(userdb.db.QueryRow(FIND_USER_BY_USERNAME_SQL, username))
}

func (userdb *UserDb) FindUserById(id uint) (*AuthUser, error) {
	return userdb.findUser(userdb.db.QueryRow(FIND_USER_BY_ID_SQL, id))
}

func (userdb *UserDb) FindUserByPublicId(publicId string) (*AuthUser, error) {
	return userdb.findUser(userdb.db.QueryRow(FIND_USER_BY_PUBLIC_ID_SQL, publicId))
}

func (userdb *UserDb) findUser(row *sql.Row) (*AuthUser, error) {

	var authUser AuthUser
	//var updatedAt int64

	err := row.Scan(&authUser.Id,
		&authUser.PublicId,
		&authUser.FirstName,
		&authUser.LastName,
		&authUser.Username,
		&authUser.Email,
		&authUser.IsLocked,
		&authUser.HashedPassword,
		&authUser.EmailVerifiedAt,
		&authUser.CreatedAt,
		&authUser.UpdatedAt)

	if err != nil {
		return nil, err
	}

	//authUser.UpdatedAt = time.Duration(updatedAt)

	err = userdb.AddRolesToUser(&authUser)

	if err != nil {
		return nil, err
	}

	err = userdb.AddApiKeysToUser(&authUser)

	if err != nil {
		return nil, err
	}

	return &authUser, nil
}

func (userdb *UserDb) FindUserByApiKey(key string) (*AuthUser, error) {

	if !IsValidUUID(key) {
		return nil, fmt.Errorf("api key is not in valid format")
	}

	var id uint
	var userId uint
	//var createdAt int64

	err := userdb.db.QueryRow(FIND_USER_BY_API_KEY_SQL, key).Scan(&id,
		&userId, &key)

	if err != nil {
		return nil, err
	}

	return userdb.FindUserById(userId)
}

func (userdb *UserDb) AddRolesToUser(authUser *AuthUser) error {

	roles, err := userdb.UserRoleList(authUser)

	if err != nil {
		return err //fmt.Errorf("there was an error with the database query")
	}

	authUser.Roles = roles

	return nil
}

func (userdb *UserDb) UserRoleList(user *AuthUser) ([]string, error) {

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

func (userdb *UserDb) AddApiKeysToUser(authUser *AuthUser) error {

	keys, err := userdb.UserApiKeys(authUser)

	if err != nil {
		return err //fmt.Errorf("there was an error with the database query")
	}

	authUser.ApiKeys = keys

	return nil
}

func (userdb *UserDb) UserApiKeys(user *AuthUser) ([]string, error) {

	rows, err := userdb.db.Query(USER_API_KEYS_SQL, user.Id)

	if err != nil {
		return nil, fmt.Errorf("user roles not found")
	}

	defer rows.Close()

	keys := make([]string, 0, 10)

	var id uint
	var key string

	for rows.Next() {

		err := rows.Scan(&id, &key)

		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}

	return keys, nil
}

func (userdb *UserDb) UserRoles(user *AuthUser) ([]*Role, error) {

	rows, err := userdb.db.Query(roles_SQL, user.Id)

	if err != nil {
		return nil, fmt.Errorf("user roles not found")
	}

	defer rows.Close()

	roles := make([]*Role, 0, 10)

	for rows.Next() {
		var role Role
		err := rows.Scan(&role.Id, &role.PublicId, &role.Name, &role.Description)

		if err != nil {
			return nil, fmt.Errorf("user roles not found")
		}

		roles = append(roles, &role)
	}

	return roles, nil
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

	rows, err := userdb.db.Query(ROLES_SQL)

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

func (userdb *UserDb) FindRoleByName(name string) (*Role, error) {

	var role Role

	err := userdb.db.QueryRow(ROLE_SQL, name).Scan(&role.Id,
		&role.PublicId,
		&role.Name,
		&role.Description)

	if err != nil {
		return nil, err
	}

	return &role, err
}

func (userdb *UserDb) UserPermissions(user *AuthUser) ([]*Permission, error) {

	rows, err := userdb.db.Query(permissions_SQL, user.Id)

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

	_, err := userdb.db.Exec(SET_EMAIL_IS_VERIFIED_SQL, userId)

	if err != nil {
		return err
	}

	// _, err = userdb.setOtpStmt.Exec("", userId)

	// if err != nil {
	// 	return false
	// }

	return nil
}

func (userdb *UserDb) SetPassword(user *AuthUser, password string) error {
	if user.IsLocked {
		return fmt.Errorf("account is locked and cannot be edited")
	}

	var err error

	err = CheckPassword(password)

	if err != nil {
		return err
	}

	hash := HashPassword(password)

	_, err = userdb.db.Exec(SET_PASSWORD_SQL, hash, user.PublicId)

	if err != nil {
		return fmt.Errorf("could not update password")
	}

	return err
}

// func (userdb *UserDb) SetUsername(publicId string, username string) error {

// 	err := CheckUsername(username)

// 	if err != nil {
// 		return err
// 	}

// 	db, err := userdb.NewConn()

// 	if err != nil {
// 		return err
// 	}

// 	defer db.Close()

// 	_, err = db.Exec(SET_USERNAME_SQL, username, publicId)

// 	if err != nil {
// 		return fmt.Errorf("could not update username")
// 	}

// 	return err
// }

// func (userdb *UserDb) SetName(publicId string, firstName string, lastName string) error {
// 	err := CheckName(firstName)

// 	if err != nil {
// 		return err
// 	}

// 	err = CheckName(lastName)

// 	if err != nil {
// 		return err
// 	}

// 	db, err := userdb.NewConn()

// 	if err != nil {
// 		return err
// 	}

// 	defer db.Close()

// 	_, err = db.Exec(SET_NAME_SQL, publicId, firstName, lastName)

// 	if err != nil {
// 		return fmt.Errorf("could not update name")
// 	}

// 	return err
// }

func (userdb *UserDb) SetUserInfo(user *AuthUser,
	username string,
	firstName string,
	lastName string,
	adminMode bool) error {

	if !adminMode && user.IsLocked {
		return fmt.Errorf("account is locked and cannot be edited")
	}

	err := CheckUsername(username)

	if err != nil {
		return err
	}

	err = CheckName(firstName)

	if err != nil {
		return err
	}

	// err = CheckName(lastName)

	// if err != nil {
	// 	return err

	_, err = userdb.db.Exec(SET_INFO_SQL, username, firstName, lastName, user.PublicId)

	if err != nil {
		log.Debug().Msgf("%s", err)
		return fmt.Errorf("could not update user info")
	}

	return err
}

// func (userdb *UserDb) SetEmail(publicId string, email string) error {
// 	address, err := mail.ParseAddress(email)

// 	if err != nil {
// 		return err
// 	}

// 	return userdb.SetEmailAddress(publicId, address)
// }

func (userdb *UserDb) SetEmailAddress(user *AuthUser, address *mail.Address, adminMode bool) error {

	if !adminMode && user.IsLocked {
		return fmt.Errorf("account is locked and cannot be edited")
	}

	_, err := userdb.db.Exec(SET_EMAIL_SQL, address.Address, user.PublicId)

	if err != nil {
		return fmt.Errorf("could not update email address")
	}

	return err
}

func (userdb *UserDb) SetUserRoles(user *AuthUser, roles []string, adminMode bool) error {
	if !adminMode && user.IsLocked {
		return fmt.Errorf("account is locked and cannot be edited")
	}

	// remove existing roles,
	_, err := userdb.db.Exec(DELETE_roles_SQL, user.Id)

	if err != nil {
		return err
	}

	for _, role := range roles {
		err = userdb.AddRoleToUser(user, role, adminMode)

		if err != nil {
			return err
		}
	}

	return nil
}

func (userdb *UserDb) AddRoleToUser(user *AuthUser, roleName string, adminMode bool) error {
	if !adminMode && user.IsLocked {
		return fmt.Errorf("account is locked and cannot be edited")
	}

	var role *Role

	role, err := userdb.FindRoleByName(roleName)

	if err != nil {
		return err
	}

	_, err = userdb.db.Exec(INSERT_USER_ROLE_SQL, user.Id, role.Id)

	if err != nil {
		return err
	}

	return nil
}

func (userdb *UserDb) CreateApiKeyForUser(user *AuthUser, adminMode bool) error {
	if !adminMode && user.IsLocked {
		return fmt.Errorf("account is locked and cannot be edited")
	}

	_, err := userdb.db.Exec(INSERT_APK_KEY_SQL, user.Id, Uuid())

	if err != nil {
		return err
	}

	return nil
}

// func (userdb *UserDb) SetOtp(userId string, otp string) error {
// 	_, err := userdb.setOtpStmt.Exec(otp, userId)

// 	return err
// }

func (userdb *UserDb) CreateUserFromSignup(user *LoginBodyReq) (*AuthUser, error) {
	email, err := mail.ParseAddress(user.Email)

	if err != nil {
		return nil, err
	}

	// The default username is email address unless a username is provided
	userName := email.Address

	if user.Username != "" {
		userName = user.Username
	}

	// assume email is not verified
	return userdb.CreateUser(userName, email, user.Password, user.FirstName, user.LastName, false)
}

// Gets the user info from the database and auto creates user if
// user does not exist since we Auth0 has authenticated them
func (userdb *UserDb) CreateUserFromAuth0(name string, email *mail.Address) (*AuthUser, error) {
	authUser, err := userdb.FindUserByEmail(email)

	if err == nil {
		return authUser, nil
	}

	firstName := ""
	lastName := ""

	if !strings.Contains(name, "@") {
		tokens := strings.SplitN(name, " ", 2)

		firstName = tokens[0]

		if len(tokens) > 1 {
			lastName = tokens[1]
		}
	}

	// user does not exist so create
	return userdb.CreateUser(email.Address, email, "", firstName, lastName, true)

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

	// Check if user exists and if they do, check passwords match.
	// We don't care about errors because errors signify the user
	// doesn't exist so we can continue and make the user
	authUser, _ := userdb.FindUserByEmail(email)

	if authUser != nil {
		// user already exists so check if verified

		if authUser.EmailVerifiedAt > EMAIL_NOT_VERIFIED_TIME_S {
			return nil, fmt.Errorf("user already registered: please sign up with a different email address")
		}

		// if user is not verified, update the password since we assume
		// rightful owner of email address will keep trying until verified
		// this is to stop people blocking creation of accounts by just
		// signing up with email addresses they have no intention of
		// verifying
		err := userdb.SetPassword(authUser, password)

		if err != nil {
			return nil, fmt.Errorf("user already registered: please sign up with another email address")
		}

		// ensure user is the updated version
		return userdb.FindUserById(authUser.Id)
	}

	// try to create user if user does not exist

	// Create a publicId for the user id
	publicId := NanoId()

	hash := ""

	// empty passwords indicate passwordless
	if password != "" {
		hash = HashPassword(password)
	}

	// default to unverified i.e. if time is epoch (1970) assume
	// unverified
	emailVerifiedAt := EPOCH_DATE

	if emailIsVerified {
		emailVerifiedAt = time.Now().Format(time.RFC3339)
	}

	log.Debug().Msgf("%s %s %s", publicId, email.Address, emailVerifiedAt)

	_, err = userdb.db.Exec(
		INSERT_USER_SQL,
		publicId,
		userName,
		email.Address,
		hash,
		firstName,
		lastName,
		emailVerifiedAt,
	)

	if err != nil {
		return nil, err
	}

	// Call function again to get the user details
	authUser, err = userdb.FindUserByPublicId(publicId)

	if err != nil {
		return nil, err
	}

	// Give user standard role and ability to login
	err = userdb.AddRoleToUser(authUser, ROLE_USER, true)

	if err != nil {
		return nil, err
	}

	err = userdb.AddRoleToUser(authUser, ROLE_SIGNIN, true)

	if err != nil {
		return nil, err
	}

	err = userdb.CreateApiKeyForUser(authUser, true)

	if err != nil {
		return nil, err
	}

	// return the updated version
	return userdb.FindUserById(authUser.Id)
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
