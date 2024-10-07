package auth

import (
	"context"
	"fmt"
	"net/mail"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/antonybholmes/go-sys"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

// See https://echo.labstack.com/docs/cookbook/jwt#login

// partially based on https://betterprogramming.pub/hands-on-with-jwt-in-golang-8c986d1bb4c0

const USERS_SQL string = `SELECT 
	id, public_id, first_name, last_name, username, email, password, FLOOR(EXTRACT(EPOCH FROM email_verified_at)) as email_verified_at, FLOOR(EXTRACT(EPOCH FROM updated_at)) as updated_at
	FROM users 
	LIMIT $1
	OFFSET $1`

const FIND_USER_BY_ID_SQL string = `SELECT 
	id, public_id, first_name, last_name, username, email, password, FLOOR(EXTRACT(EPOCH FROM email_verified_at)) as email_verified_at, FLOOR(EXTRACT(EPOCH FROM updated_at)) as updated_at
	FROM users 
	WHERE users.id = $1`

const FIND_USER_BY_PUBLIC_ID_SQL string = `SELECT 
	id, public_id, first_name, last_name, username, email, password, FLOOR(EXTRACT(EPOCH FROM email_verified_at)) as email_verified_at, FLOOR(EXTRACT(EPOCH FROM updated_at)) as updated_at
	FROM users 
	WHERE users.public_id = $1`

const FIND_USER_BY_EMAIL_SQL string = `SELECT 
	id, public_id, first_name, last_name, username, email, password, FLOOR(EXTRACT(EPOCH FROM email_verified_at)) as email_verified_at, FLOOR(EXTRACT(EPOCH FROM updated_at)) as updated_at
	FROM users 
	WHERE users.email = $1`

const FIND_USER_BY_USERNAME_SQL string = `SELECT 
	id, public_id, first_name, last_name, username, email, password, FLOOR(EXTRACT(EPOCH FROM email_verified_at)) as email_verified_at, FLOOR(EXTRACT(EPOCH FROM updated_at)) as updated_at
	FROM users 
	WHERE users.username = $1`

const ROLES_SQL string = `SELECT 
	user_roles.id, user_roles.public_id, user_roles.name, user_roles.description
	FROM user_roles 
	ORDER BY user_roles.name`

const USER_PERMISSIONS_SQL string = `SELECT DISTINCT 
	permissions.id, permissions.public_id, permissions.name, permissions.description
	FROM users_roles, roles_permissions, permissions 
	WHERE users_roles.user_id = $1 AND roles_permissions.role_id = users_roles.role_id AND 
	permissions.id = roles_permissions.permission_id 
	ORDER BY permissions.name`

const USER_ROLES_SQL string = `SELECT DISTINCT 
	user_roles.id, user_roles.public_id, user_roles.name, user_roles.description
	FROM users_roles, user_roles 
	WHERE users_roles.user_id = $1 AND user_roles.id = users_roles.role_id 
	ORDER BY user_roles.name`

const INSERT_USER_SQL = `INSERT INTO users 
	(public_id, username, email, password, first_name, last_name, email_verified_at) 
	VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING`

const DELETE_USER_ROLES_SQL = "DELETE FROM users_roles WHERE user_id = $1"
const INSERT_USER_ROLE_SQL = "INSERT INTO users_roles (user_id, role_id) VALUES($1, $2) ON CONFLICT DO NOTHING"

const SET_EMAIL_IS_VERIFIED_SQL = `UPDATE users SET email_verified_at = now() WHERE users.public_id = $1`
const SET_PASSWORD_SQL = `UPDATE users SET password = $1 WHERE users.public_id = $2`
const SET_USERNAME_SQL = `UPDATE users SET username = $1 WHERE users.public_id = $2`

// const SET_NAME_SQL = `UPDATE users SET first_name = $1, last_name = $1 WHERE users.public_id = $1`
const SET_INFO_SQL = `UPDATE users SET username = $1, first_name = $2, last_name = $3 WHERE users.public_id = $4`
const SET_EMAIL_SQL = `UPDATE users SET email = $1 WHERE users.public_id = $2`

const DELETE_USER_SQL = `DELETE FROM users WHERE public_id = $1`

const COUNT_USERS_SQL = `SELECT COUNT(ID) FROM users`

const ROLE_SQL = `SELECT 
	user_roles.id, 
	user_roles.public_id, 
	user_roles.name,
	user_roles.description 
	FROM user_roles WHERE user_roles.name = $1`

const MIN_PASSWORD_LENGTH int = 8
const MIN_NAME_LENGTH int = 4

type UserDb struct {
	db  *pgxpool.Pool
	ctx context.Context
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
	ctx := context.Background()

	log.Debug().Msgf("conn %s", os.Getenv("DATABASE_URL"))

	db := sys.Must(pgxpool.New(ctx, os.Getenv("DATABASE_URL")))

	log.Debug().Msgf("Connected!")

	return &UserDb{
		db:  db,
		ctx: ctx,
		// findUserByPublicIdStmt: sys.Must(db.Prepare(FIND_USER_BY_PUBLIC_ID_SQL)),
		// findUserByEmailStmt:    sys.Must(db.Prepare(FIND_USER_BY_EMAIL_SQL)),
		// findUserByUsernameStmt: sys.Must(db.Prepare(FIND_USER_BY_USERNAME_SQL)),
		// setInfoStmt:            sys.Must(db.Prepare(SET_INFO_SQL)),
		// setEmailStmt:           sys.Must(db.Prepare(SET_EMAIL_SQL)),
		// usersStmt:              sys.Must(db.Prepare(USERS_SQL)),
		// userRolesStmt:          sys.Must(db.Prepare(USER_ROLES_SQL)),
		// insertUserStmt:         sys.Must(db.Prepare(INSERT_USER_SQL)),
		// insertUserRoleStmt:     sys.Must(db.Prepare(INSERT_USER_ROLE_SQL)),
		// rolesStmt:              sys.Must(db.Prepare(ROLES_SQL)),
		// roleStmt:               sys.Must(db.Prepare(ROLE_SQL)),
		// deleteUserStmt:         sys.Must(db.Prepare(DELETE_USER_SQL))
	}
}

func (userdb *UserDb) Db() *pgxpool.Pool {
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
	PASSWORD_REGEX = regexp.MustCompile(`^[A-Za-z\d\@\$\!\%\*\#\$1\&\.\~\^\-]*$`)
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

	err := userdb.db.QueryRow(userdb.ctx, COUNT_USERS_SQL).Scan(&n)

	if err != nil {
		return 0, err
	}

	return n, nil
}

func (userdb *UserDb) Users(offset uint, records uint) ([]*AuthUserAdminView, error) {

	rows, err := userdb.db.Query(userdb.ctx, USERS_SQL, offset, records)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	authUsers := make([]*AuthUserAdminView, 0, records)

	var updatedAt int64

	for rows.Next() {
		var authUser AuthUserAdminView
		err := rows.Scan(&authUser.Id,
			&authUser.PublicId,
			&authUser.FirstName,
			&authUser.LastName,
			&authUser.Username,
			&authUser.Email,
			&authUser.HashedPassword,
			&authUser.EmailVerifiedAt,
			&updatedAt)

		if err != nil {
			return nil, err
		}

		authUser.UpdatedAt = time.Duration(updatedAt)

		userdb.updateUserRoles(&authUser)

		authUsers = append(authUsers, &authUser)
	}

	return authUsers, nil
}

func (userdb *UserDb) DeleteUser(publicId string) error {

	authUser, err := userdb.FindUserByPublicId(publicId)

	if err != nil {
		return err
	}

	roles, err := userdb.RoleList(authUser.Id)

	if err != nil {
		return err
	}

	claim := MakeClaim(roles)

	if strings.Contains(claim, ROLE_SUPER) {
		return fmt.Errorf("cannot delete superuser account")
	}

	_, err = userdb.db.Exec(userdb.ctx, DELETE_USER_SQL, publicId)

	if err != nil {
		return err
	}

	return nil
}

func (userdb *UserDb) FindUserByEmail(email *mail.Address) (*AuthUser, error) {
	var authUser AuthUser
	var updatedAt int64

	err := userdb.db.QueryRow(userdb.ctx, FIND_USER_BY_EMAIL_SQL, email.Address).Scan(&authUser.Id,
		&authUser.PublicId,
		&authUser.FirstName,
		&authUser.LastName,
		&authUser.Username,
		&authUser.Email,
		&authUser.HashedPassword,
		&authUser.EmailVerifiedAt,
		&updatedAt)

	if err != nil {
		return nil, err
	}

	authUser.UpdatedAt = time.Duration(updatedAt)

	//err = userdb.updateUserRoles(&authUser)

	// if err != nil {
	// 	return nil, err
	// }

	return &authUser, nil
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

	var authUser AuthUser
	var updatedAt int64

	err = userdb.db.QueryRow(userdb.ctx, FIND_USER_BY_USERNAME_SQL, username).Scan(&authUser.Id,
		&authUser.PublicId,
		&authUser.FirstName,
		&authUser.LastName,
		&authUser.Username,
		&authUser.Email,
		&authUser.HashedPassword,
		&authUser.EmailVerifiedAt,
		&updatedAt)

	if err != nil {
		log.Debug().Msgf("err %s", err)
		return nil, err
	}

	authUser.UpdatedAt = time.Duration(updatedAt)

	// err = userdb.updateUserRoles(&authUser)

	// if err != nil {
	// 	return nil, err
	// }

	return &authUser, nil
}

func (userdb *UserDb) FindUserById(id int) (*AuthUser, error) {

	var authUser AuthUser
	var updatedAt int64

	err := userdb.db.QueryRow(userdb.ctx, FIND_USER_BY_ID_SQL, id).Scan(&authUser.Id,
		&authUser.PublicId,
		&authUser.FirstName,
		&authUser.LastName,
		&authUser.Username,
		&authUser.Email,
		&authUser.HashedPassword,
		&authUser.EmailVerifiedAt,
		&updatedAt)

	if err != nil {
		return nil, err
	}

	authUser.UpdatedAt = time.Duration(updatedAt)

	// err = userdb.updateUserRoles(&authUser)

	// if err != nil {
	// 	return nil, err
	// }

	return &authUser, nil
}

func (userdb *UserDb) FindUserByPublicId(publicId string) (*AuthUser, error) {

	var authUser AuthUser
	var updatedAt int64
	//var createdAt int64

	err := userdb.db.QueryRow(userdb.ctx, FIND_USER_BY_PUBLIC_ID_SQL, publicId).Scan(&authUser.Id,
		&authUser.PublicId,
		&authUser.FirstName,
		&authUser.LastName,
		&authUser.Username,
		&authUser.Email,
		&authUser.HashedPassword,
		&authUser.EmailVerifiedAt,
		&updatedAt)

	if err != nil {
		return nil, err
	}

	authUser.UpdatedAt = time.Duration(updatedAt)

	// err = userdb.updateUserRoles(&authUser)

	// if err != nil {
	// 	return nil, err
	// }

	return &authUser, nil
}

func (userdb *UserDb) updateUserRoles(authUser *AuthUserAdminView) error {

	roles, err := userdb.RoleList(authUser.Id)

	if err != nil {
		return err //fmt.Errorf("there was an error with the database query")
	}

	authUser.Roles = roles

	return nil
}

func (userdb *UserDb) RoleList(userId uint) ([]string, error) {

	roles, err := userdb.UserRoles(userId)

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

	rows, err := userdb.db.Query(userdb.ctx, ROLES_SQL)

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

	var role Role

	err := userdb.db.QueryRow(userdb.ctx, ROLE_SQL, name).Scan(&role.Id,
		&role.PublicId,
		&role.Name,
		&role.Description)

	if err != nil {
		return nil, err
	}

	return &role, err
}

func (userdb *UserDb) UserRoles(userId uint) ([]*Role, error) {

	rows, err := userdb.db.Query(userdb.ctx, USER_ROLES_SQL, userId)

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

	rows, err := userdb.db.Query(userdb.ctx, USER_PERMISSIONS_SQL, user.Id)

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

	_, err := userdb.db.Exec(userdb.ctx, SET_EMAIL_IS_VERIFIED_SQL, userId)

	if err != nil {
		return err
	}

	// _, err = userdb.setOtpStmt.Exec("", userId)

	// if err != nil {
	// 	return false
	// }

	return nil
}

func (userdb *UserDb) SetPassword(publicId string, password string) error {
	var err error

	err = CheckPassword(password)

	if err != nil {
		return err
	}

	hash := HashPassword(password)

	_, err = userdb.db.Exec(userdb.ctx, SET_PASSWORD_SQL, hash, publicId)

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

func (userdb *UserDb) SetUserInfo(publicId string,
	username string,
	firstName string,
	lastName string) error {

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

	_, err = userdb.db.Exec(userdb.ctx, SET_INFO_SQL, username, firstName, lastName, publicId)

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

func (userdb *UserDb) SetEmailAddress(publicId string, address *mail.Address) error {

	_, err := userdb.db.Exec(userdb.ctx, SET_EMAIL_SQL, address.Address, publicId)

	if err != nil {
		return fmt.Errorf("could not update email address")
	}

	return err
}

func (userdb *UserDb) SetUserRoles(user *AuthUser, roles []string) error {

	// remove existing roles,
	_, err := userdb.db.Exec(userdb.ctx, DELETE_USER_ROLES_SQL, user.Id)

	if err != nil {
		return err
	}

	for _, role := range roles {
		err = userdb.AddRoleToUser(user, role)

		if err != nil {
			return err
		}
	}

	return nil
}

func (userdb *UserDb) AddRoleToUser(user *AuthUser, roleName string) error {

	var role *Role

	role, err := userdb.Role(roleName)

	if err != nil {
		return err
	}

	_, err = userdb.db.Exec(userdb.ctx, INSERT_USER_ROLE_SQL, user.Id, role.Id)

	if err != nil {
		return err
	}

	return nil
}

// func (userdb *UserDb) SetOtp(userId string, otp string) error {
// 	_, err := userdb.setOtpStmt.Exec(otp, userId)

// 	return err
// }

func (userdb *UserDb) CreateUserFromSignup(user *LoginReq) (*AuthUser, error) {
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
	authUser, err := userdb.FindUserByEmail(email)

	// try to create user if user does not exist
	if err != nil {
		// Create a publicId for the user id
		publicId := NanoId()

		hash := ""

		// empty passwords indicate passwordless
		if password != "" {
			hash = HashPassword(password)
		}

		emailVerifiedAt := "epoch"

		if emailIsVerified {
			emailVerifiedAt = "now()"
		}

		log.Debug().Msgf("%s %s %s", publicId, email.Address, emailVerifiedAt)

		_, err = userdb.db.Exec(userdb.ctx,
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
		authUser, err = userdb.FindUserByEmail(email)

		if err != nil {
			return nil, err
		}
	} else {
		// user already exists so check if verified

		if authUser.EmailVerifiedAt > 0 {
			return nil, fmt.Errorf("user already registered:please sign up with a different email address")
		}

		// if user is not verified, update the password since we assume
		// rightful owner of email address will keep trying until verified
		// this is to stop people blocking creation of accounts by just
		// signing up with email addresses they have no intention of
		// verifying
		err := userdb.SetPassword(password, authUser.PublicId)

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
