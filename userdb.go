package auth

import (
	"database/sql"
	"fmt"
	"net/mail"
	"regexp"
	"strings"

	"github.com/antonybholmes/go-sys"
	"github.com/rs/zerolog/log"
)

// See https://echo.labstack.com/docs/cookbook/jwt#login

// partially based on https://betterprogramming.pub/hands-on-with-jwt-in-golang-8c986d1bb4c0

const USERS_SQL string = `SELECT id, public_id, first_name, last_name, username, email, password, email_verified, strftime('%s', updated_on) 
	FROM users 
	OFFSET ?1
	LIMIT ?2`

const FIND_USER_BY_ID_SQL string = `SELECT 
	id, public_id, first_name, last_name, username, email, password, email_verified, strftime('%s', updated_on) 
	FROM users 
	WHERE users.id = ?1`

const FIND_USER_BY_PUBLIC_ID_SQL string = `SELECT 
	id, public_id, first_name, last_name, username, email, password, email_verified, strftime('%s', updated_on) 
	FROM users 
	WHERE users.public_id = ?1`

const FIND_USER_BY_EMAIL_SQL string = `SELECT 
	id, public_id, first_name, last_name, username, email, password, email_verified, strftime('%s', updated_on) 
	FROM users 
	WHERE users.email = ?1`

const FIND_USER_BY_USERNAME_SQL string = `SELECT 
	id, public_id, first_name, last_name, username, email, password, email_verified, strftime('%s', updated_on) 
	FROM users 
	WHERE users.username = ?1`

const ROLES_SQL string = `SELECT roles.public_id, roles.name, roles.description
	FROM roles 
	ORDER BY roles.name`

// const USER_ROLE_PERMISSIONS_SQL string = `SELECT DISTINCT roles.public_id AS role_uuid, roles.name AS role_name, permissions.public_id AS permission_uuid, permissions.name AS permission_name
// 	FROM user_roles, role_permissions, permissions
// 	WHERE user_roles.user_uuid = ?1 AND role_permissions.role_uuid = user_roles.role_uuid AND permissions.public_id = role_permissions.permission_uuid
// 	ORDER BY roles.name, permissions.name`

const USER_PERMISSIONS string = `SELECT DISTINCT permissions.id, permissions.public_id, permissions.name, permissions.description
	FROM users_roles, roles_permissions, permissions 
	WHERE users_roles.user_id = ?1 AND roles_permissions.role_id = users_roles.role_id AND permissions.id = roles_permissions.permission_id 
	ORDER BY permissions.name`

const USER_ROLES string = `SELECT DISTINCT roles.id, roles.public_id, roles.name, roles.description
	FROM users_roles, roles 
	WHERE users_roles.user_id = ?1 AND roles.id = users_roles.role_id 
	ORDER BY roles.name`

const CREATE_USER_SQL = `INSERT INTO users (public_id, first_name, last_name, username, email, password) VALUES(?, ?, ?, ?, ?, ?)`

const SET_EMAIL_VERIFIED_SQL = `UPDATE users SET email_verified = 1 WHERE users.public_id = ?`
const SET_PASSWORD_SQL = `UPDATE users SET password = ? WHERE users.public_id = ?`
const SET_USERNAME_SQL = `UPDATE users SET username = ? WHERE users.public_id = ?`
const SET_NAME_SQL = `UPDATE users SET first_name = ?, last_name = ? WHERE users.public_id = ?`
const SET_INFO_SQL = `UPDATE users SET username = ?2, first_name = ?3, last_name = ?4 WHERE users.public_id = ?1`
const SET_EMAIL_SQL = `UPDATE users SET email = ? WHERE users.public_id = ?`

const MIN_PASSWORD_LENGTH int = 8
const MIN_NAME_LENGTH int = 4

const STANDARD_ROLE = "Standard"

type UserDb struct {
	db                   *sql.DB
	setEmailVerifiedStmt *sql.Stmt
	setPasswordStmt      *sql.Stmt
	setUsernameStmt      *sql.Stmt
	setNameStmt          *sql.Stmt
	setInfoStmt          *sql.Stmt
	setEmailStmt         *sql.Stmt
	file                 string
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

	db := sys.Must(sql.Open("sqlite3", file))

	return &UserDb{file: file,
		db: db,
		//findUserByEmailStmt:    sys.Must(db.Prepare(FIND_USER_BY_EMAIL_SQL)),
		//findUserByUsernameStmt: sys.Must(db.Prepare(FIND_USER_BY_USERNAME_SQL)),
		//findUserByIdStmt:       sys.Must(db.Prepare(FIND_USER_BY_UUID_SQL)),
		//createUserStmt:       sys.Must(db.Prepare(CREATE_USER_SQL)),
		setEmailVerifiedStmt: sys.Must(db.Prepare(SET_EMAIL_VERIFIED_SQL)),
		setPasswordStmt:      sys.Must(db.Prepare(SET_PASSWORD_SQL)),
		setUsernameStmt:      sys.Must(db.Prepare(SET_USERNAME_SQL)),
		setNameStmt:          sys.Must(db.Prepare(SET_NAME_SQL)),
		setInfoStmt:          sys.Must(db.Prepare(SET_INFO_SQL)),
		setEmailStmt:         sys.Must(db.Prepare(SET_EMAIL_SQL)),
		//rolesStmt:              sys.Must(db.Prepare(ROLES_SQL)),
		//permissionsStmt:        sys.Must(db.Prepare(USER_PERMISSIONS))
	}
}

func (userdb *UserDb) Close() {
	if userdb.db != nil {
		userdb.db.Close()
	}
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

		userdb.addRoles(&authUser)

		authUsers = append(authUsers, &authUser)
	}

	return authUsers, nil
}

// func (userdb *UserDb) FindUserByUsernameOrEmail(id string) (*AuthUser, error) {
// 	authUser, err := userdb.FindUserByUsername(id)

// 	if err == nil {
// 		return authUser, nil
// 	}

// 	// try finding by email

// 	email, err := mail.ParseAddress(id)

// 	if err == nil {
// 		// also check if username is valid email and try to login
// 		// with that
// 		authUser, err = userdb.FindUserByEmail(email)

// 		if err == nil {
// 			return authUser, nil
// 		}
// 	}

// 	authUser, err = userdb.FindUserByUuid(id)

// 	if err != nil {
// 		return nil, err
// 	}

// 	err = userdb.addPermissions((authUser))

// 	if err != nil {
// 		return nil, err
// 	}

// 	return authUser, nil
// }

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

	err = userdb.addRoles(&authUser)

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

	err = userdb.addRoles(&authUser)

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

	err = userdb.addRoles(&authUser)

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

	err = userdb.addRoles(&authUser)

	if err != nil {
		return nil, err
	}

	return &authUser, nil
}

func (userdb *UserDb) addRoles(authUser *AuthUser) error {

	roles, err := userdb.RoleList(authUser)

	if err != nil {
		return err //fmt.Errorf("there was an error with the database query")
	}

	log.Debug().Msgf("ss perm %v", roles)

	authUser.Roles = roles

	return nil
}

func (userdb *UserDb) RoleList(user *AuthUser) ([]string, error) {

	roles, err := userdb.UserRoles(user)

	if err != nil {
		return nil, err
	}

	ret := make([]string, len(*roles))

	for ri, role := range *roles {
		ret[ri] = role.Name
	}

	return ret, nil

}

func (userdb *UserDb) PermissionList(user *AuthUser) (*[]string, error) {

	permissions, err := userdb.UserPermissions(user)

	if err != nil {
		return nil, err
	}

	ret := make([]string, len(*permissions))

	for pi, permission := range *permissions {
		ret[pi] = permission.Name
	}

	return &ret, nil

}

func (userdb *UserDb) Query(query string, args ...any) (*sql.Rows, error) {
	return userdb.db.Query(query, args...)
}

func (userdb *UserDb) QueryRow(query string, args ...any) *sql.Row {
	return userdb.db.QueryRow(query, args...)
}

func (userdb *UserDb) Roles() (*[]Role, error) {

	rows, err := userdb.Query("SELECT public_id, name FROM roles ORDER by roles.name")

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var roles []Role

	for rows.Next() {
		var role Role
		err := rows.Scan(&role.PublicId, &role.Name)

		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}

	return &roles, nil
}

func (userdb *UserDb) Role(name string) (*Role, error) {
	var role Role
	err := userdb.QueryRow("SELECT public_id, name FROM roles WHERE roles.name = ?", name).Scan(role.PublicId, role.Name)

	if err != nil {
		return nil, err
	}

	return &role, err
}

func (userdb *UserDb) UserRoles(user *AuthUser) (*[]Role, error) {

	db, err := sql.Open("sqlite3", userdb.file) //not clear on what is needed for the user and password

	if err != nil {
		return nil, err
	}

	defer db.Close()

	rows, err := db.Query(USER_ROLES, user.Id)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var roles []Role

	for rows.Next() {
		var role Role
		err := rows.Scan(&role.Id, &role.PublicId, &role.Name, &role.Description)

		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}

	return &roles, nil
}

func (userdb *UserDb) UserPermissions(user *AuthUser) (*[]Permission, error) {

	db, err := sql.Open("sqlite3", userdb.file) //not clear on what is needed for the user and password

	if err != nil {
		return nil, err
	}

	defer db.Close()

	rows, err := db.Query(USER_PERMISSIONS, user.Id)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var permissions []Permission

	for rows.Next() {
		var permission Permission
		err := rows.Scan(&permission.Id, &permission.PublicId, &permission.Name, &permission.Description)

		if err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}

	return &permissions, nil
}

// func (userdb *UserDb) PublicUserRolePermissions(user *AuthUser) (*[]PublicRole, error) {

// 	rows, err := userdb.Query(USER_ROLE_PERMISSIONS_SQL, user.PublicId)

// 	if err != nil {
// 		return nil, err
// 	}

// 	defer rows.Close()

// 	var roleUuid string
// 	var roleName string
// 	var permissionUuid string
// 	var permissionName string
// 	var currentRole string = ""

// 	ret := make([]PublicRole, 0, 10)

// 	for rows.Next() {
// 		err := rows.Scan(&roleUuid, &roleName, &permissionUuid, &permissionName)

// 		if err != nil {
// 			return nil, err
// 		}

// 		log.Debug().Msgf("%s %s", roleName, permissionName)

// 		if roleUuid != currentRole {
// 			ret = append(ret, PublicRole{Name: roleName, Permissions: make([]string, 0, 10)})
// 			currentRole = roleUuid
// 		}

// 		idx := len(ret) - 1
// 		ret[idx].Permissions = append(ret[idx].Permissions, permissionName)
// 	}

// 	return &ret, nil
// }

func (userdb *UserDb) SetIsVerified(userId string) error {

	_, err := userdb.setEmailVerifiedStmt.Exec(userId)

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

	//log.Debug().Msgf("hash:%s:%s:", hash, password)

	_, err = userdb.setPasswordStmt.Exec(hash, public_id)

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

	_, err = userdb.setUsernameStmt.Exec(username, public_id)

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

	_, err = userdb.setNameStmt.Exec(firstName, lastName, public_id)

	if err != nil {
		return fmt.Errorf("could not update name")
	}

	return err
}

func (userdb *UserDb) SetUserInfo(public_id string, username string, firstName string, lastName string) error {

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

	log.Debug().Msgf("%s %s", public_id, username)

	_, err = userdb.setInfoStmt.Exec(public_id, username, firstName, lastName)

	log.Debug().Msgf("%s ", err)

	if err != nil {
		return fmt.Errorf("could not update user info")
	}

	return err
}

func (userdb *UserDb) SetEmail(public_id string, email string) error {
	address, err := mail.ParseAddress(email)

	if err != nil {
		return err
	}

	return userdb.SetEmailAddress(public_id, address)
}

func (userdb *UserDb) SetEmailAddress(public_id string, address *mail.Address) error {

	_, err := userdb.setEmailStmt.Exec(address.Address, public_id)

	if err != nil {
		return fmt.Errorf("could not update email address")
	}

	return err
}

func (userdb *UserDb) AddUserRole(user *AuthUser, role string) error {
	r, err := userdb.Role(role)

	if err != nil {
		return fmt.Errorf("%s role not available", role)
	}

	_, err = userdb.db.Exec("INSERT INTO user_roles (user_uuid, role_uuid) VALUES(?, ?)", user.PublicId, r.PublicId)

	if err != nil {
		return fmt.Errorf("%s role not available", role)
	}

	return nil
}

// func (userdb *UserDb) SetOtp(userId string, otp string) error {
// 	_, err := userdb.setOtpStmt.Exec(otp, userId)

// 	return err
// }

func (userdb *UserDb) CreateStandardUser(user *SignupReq) (*AuthUser, error) {
	err := CheckPassword(user.Password)

	if err != nil {
		return nil, err
	}

	email, err := mail.ParseAddress(user.Email)

	if err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite3", userdb.file) //not clear on what is needed for the user and password

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

		//log.Debug().Msgf("%s %s", user.FirstName, user.Email)

		_, err = db.Exec(CREATE_USER_SQL, public_id,
			user.FirstName,
			user.LastName,
			email.Address,
			email.Address,
			user.HashedPassword())

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
		err := userdb.SetPassword(authUser.PublicId, user.Password)

		if err != nil {
			return nil, fmt.Errorf("user already registered:please sign up with another email address")
		}
	}

	// Give user standard role

	userdb.AddUserRole(authUser, STANDARD_ROLE)

	// err = userdb.SetOtp(authUser.UserId, otp)

	// if err != nil {
	// 	return nil, fmt.Errorf("could not set otp")
	// }

	return authUser, nil
}

// Make sure password meets requirements
func CheckPassword(password string) error {
	if password != "" && len(password) < MIN_PASSWORD_LENGTH {
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
