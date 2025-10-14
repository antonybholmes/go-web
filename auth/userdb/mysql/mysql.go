package mysql

import (
	"database/sql"
	"fmt"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/antonybholmes/go-sys"
	"github.com/antonybholmes/go-web/auth"
	"github.com/antonybholmes/go-web/auth/userdb"

	"github.com/go-sql-driver/mysql"
	"github.com/rs/zerolog/log"
)

type MySQLUserDB struct {
	db *sql.DB
}

const (

	// mysql version
	SelectUsersSql string = `SELECT
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
)

func NewMySQLUserDB() *MySQLUserDB {
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

	return &MySQLUserDB{
		db: db,
	}
}

func (mydb *MySQLUserDB) Db() *sql.DB {
	return mydb.db
}

// func (mydb *mydb) PrepStmt(sql string) *sql.Stmt {
// 	stmt, ok := mydb.prepMap[sql]

// 	if ok {
// 		log.Debug().Msgf("cached stmt %s", sql)
// 		return stmt
// 	}

// 	stmt = sys.Must(mydb.db.Prepare(sql))
// 	mydb.prepMap[sql] = stmt

// 	return stmt
// }

// func (mydb *mydb) NewConn() (*sql.DB, error) {
// 	return sql.Open("sqlite3", mydb.file)
// }

// // If db is initialized, return it, otherwise create a new
// // connection and return it
// func (mydb *mydb) AutoConn(db *sql.DB) (*sql.DB, error) {
// 	if db != nil {
// 		return db, nil
// 	}

// 	db, err := mydb.NewConn() //not clear on what is needed for the user and password

// 	if err != nil {
// 		return nil, err
// 	}

// 	//defer db.Close()

// 	return db, nil
// }

// func (mydb *mydb) Close() {
// 	if mydb.db != nil {
// 		mydb.db.Close()
// 	}
// }

func (mydb *MySQLUserDB) NumUsers() (uint, error) {

	var n uint

	err := mydb.db.QueryRow(CountUsersSql).Scan(&n)

	if err != nil {
		return 0, err
	}

	return n, nil
}

func (mydb *MySQLUserDB) Users(records uint, offset uint) ([]*auth.AuthUser, error) {
	//log.Debug().Msgf("users %d %d", records, offset)

	rows, err := mydb.db.Query(UsersSql, records, offset)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	authUsers := make([]*auth.AuthUser, 0, records)

	//var createdAt time.Duration
	//var updatedAt time.Duration
	//var emailVerifiedAt int64

	for rows.Next() {
		// need to initialize slices here to avoid nil
		authUser := auth.AuthUser{
			Roles:   make([]string, 0, 5),
			ApiKeys: make([]string, 0, 5),
		}

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

		//log.Debug().Msgf("this user %v", authUser)

		err = mydb.AddRolesToUser(&authUser)

		if err != nil {
			return nil, err
		}

		authUsers = append(authUsers, &authUser)
	}

	return authUsers, nil
}

func (mydb *MySQLUserDB) DeleteUser(publicId string) error {

	authUser, err := mydb.FindUserByPublicId(publicId)

	if err != nil {
		return err
	}

	roles, err := mydb.UserRoleList(authUser)

	if err != nil {
		return err
	}

	claim := auth.MakeClaim(roles)

	if strings.Contains(claim, auth.RoleSuper) {
		return fmt.Errorf("cannot delete superuser account")
	}

	_, err = mydb.db.Exec(DeleteUserSql, publicId)

	if err != nil {
		return err
	}

	return nil
}

func (mydb *MySQLUserDB) FindUserByEmail(email *mail.Address) (*auth.AuthUser, error) {
	return mydb.findUser(mydb.db.QueryRow(FindUserByEmailSql, email.Address))
}

func (mydb *MySQLUserDB) FindUserByUsername(username string) (*auth.AuthUser, error) {

	if strings.Contains(username, "@") {
		email, err := mail.ParseAddress(username)

		if err != nil {
			return nil, err
		}

		return mydb.FindUserByEmail(email)
	}

	err := userdb.CheckUsername(username)

	if err != nil {
		return nil, err
	}

	return mydb.findUser(mydb.db.QueryRow(FindUserByUsernameSql, username))
}

func (mydb *MySQLUserDB) FindUserById(id uint) (*auth.AuthUser, error) {
	return mydb.findUser(mydb.db.QueryRow(FindUserByIdSql, id))
}

func (mydb *MySQLUserDB) FindUserByPublicId(publicId string) (*auth.AuthUser, error) {
	return mydb.findUser(mydb.db.QueryRow(FindUserByPublicIdSql, publicId))
}

func (mydb *MySQLUserDB) findUser(row *sql.Row) (*auth.AuthUser, error) {

	var authUser auth.AuthUser
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

	err = mydb.AddRolesToUser(&authUser)

	if err != nil {
		return nil, err
	}

	err = mydb.AddApiKeysToUser(&authUser)

	if err != nil {
		return nil, err
	}

	return &authUser, nil
}

func (mydb *MySQLUserDB) FindUserByApiKey(key string) (*auth.AuthUser, error) {

	if !sys.IsValidUUID(key) {
		return nil, fmt.Errorf("api key is not in valid format")
	}

	var id uint
	var userId uint
	//var createdAt int64

	err := mydb.db.QueryRow(FindUserByApiKeySql, key).Scan(&id,
		&userId, &key)

	if err != nil {
		return nil, err
	}

	return mydb.FindUserById(userId)
}

func (mydb *MySQLUserDB) AddRolesToUser(authUser *auth.AuthUser) error {

	roles, err := mydb.UserRoleList(authUser)

	if err != nil {
		return err //fmt.Errorf("there was an error with the database query")
	}

	authUser.Roles = append(authUser.Roles, roles...)

	return nil
}

func (mydb *MySQLUserDB) UserRoleList(user *auth.AuthUser) ([]string, error) {

	roles, err := mydb.UserRoles(user)

	if err != nil {
		return nil, err
	}

	ret := make([]string, len(roles))

	for ri, role := range roles {
		ret[ri] = role.Name
	}

	return ret, nil

}

func (mydb *MySQLUserDB) AddApiKeysToUser(authUser *auth.AuthUser) error {

	keys, err := mydb.UserApiKeys(authUser)

	if err != nil {
		return err //fmt.Errorf("there was an error with the database query")
	}

	authUser.ApiKeys = keys

	return nil
}

func (mydb *MySQLUserDB) UserApiKeys(user *auth.AuthUser) ([]string, error) {

	rows, err := mydb.db.Query(UsersApiKeysSql, user.Id)

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

func (mydb *MySQLUserDB) UserRoles(user *auth.AuthUser) ([]*auth.Role, error) {

	rows, err := mydb.db.Query(UserRolesSql, user.Id)

	if err != nil {
		return nil, fmt.Errorf("user roles not found")
	}

	defer rows.Close()

	roles := make([]*auth.Role, 0, 10)

	for rows.Next() {
		var role auth.Role
		err := rows.Scan(&role.Id, &role.PublicId, &role.Name, &role.Description)

		if err != nil {
			return nil, fmt.Errorf("user roles not found")
		}

		roles = append(roles, &role)
	}

	return roles, nil
}

func (mydb *MySQLUserDB) PermissionList(user *auth.AuthUser) ([]string, error) {

	permissions, err := mydb.Permissions(user)

	if err != nil {
		return nil, err
	}

	ret := make([]string, len(permissions))

	for pi, permission := range permissions {
		ret[pi] = permission.Name
	}

	return ret, nil

}

// func (mydb *mydb) Query(query string, args ...any) (*sql.Rows, error) {
// 	return mydb.db.Query(query, args...)
// }

// func (mydb *mydb) QueryRow(query string, args ...any) *sql.Row {
// 	db, err := sql.Open("sqlite3", mydb.file) //not clear on what is needed for the user and password

// 	if err != nil {
// 		return nil, err
// 	}

// 	defer db.Close()
// 	return mydb.db.QueryRow(query, args...)
// }

func (mydb *MySQLUserDB) Roles() ([]*auth.Role, error) {

	rows, err := mydb.db.Query(RolesSql)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var roles []*auth.Role

	for rows.Next() {
		var role auth.Role
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

func (mydb *MySQLUserDB) FindRoleByName(name string) (*auth.Role, error) {

	var role auth.Role

	err := mydb.db.QueryRow(RoleSql, name).Scan(&role.Id,
		&role.PublicId,
		&role.Name,
		&role.Description)

	if err != nil {
		return nil, err
	}

	return &role, err
}

func (mydb *MySQLUserDB) Permissions(user *auth.AuthUser) ([]*auth.Permission, error) {

	rows, err := mydb.db.Query(PermissionsSql, user.Id)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	permissions := make([]*auth.Permission, 0, 10)

	for rows.Next() {
		var permission auth.Permission

		err := rows.Scan(&permission.Id, &permission.PublicId, &permission.Name, &permission.Description)

		if err != nil {
			return nil, err
		}

		permissions = append(permissions, &permission)
	}

	return permissions, nil
}

func (mydb *MySQLUserDB) SetIsVerified(userId string) error {

	_, err := mydb.db.Exec(SetEmailVerifiedSql, userId)

	if err != nil {
		return err
	}

	// _, err = mydb.setOtpStmt.Exec("", userId)

	// if err != nil {
	// 	return false
	// }

	return nil
}

func (mydb *MySQLUserDB) SetPassword(user *auth.AuthUser, password string) error {
	if user.IsLocked {
		return fmt.Errorf("account is locked and cannot be edited")
	}

	var err error

	err = userdb.CheckPassword(password)

	if err != nil {
		return err
	}

	hash := auth.HashPassword(password)

	_, err = mydb.db.Exec(SetPasswordSql, hash, user.PublicId)

	if err != nil {
		return fmt.Errorf("could not update password")
	}

	return err
}

// func (mydb *mydb) SetUsername(publicId string, username string) error {

// 	err := CheckUsername(username)

// 	if err != nil {
// 		return err
// 	}

// 	db, err := mydb.NewConn()

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

// func (mydb *mydb) SetName(publicId string, firstName string, lastName string) error {
// 	err := CheckName(firstName)

// 	if err != nil {
// 		return err
// 	}

// 	err = CheckName(lastName)

// 	if err != nil {
// 		return err
// 	}

// 	db, err := mydb.NewConn()

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

func (mydb *MySQLUserDB) SetUserInfo(user *auth.AuthUser,
	username string,
	firstName string,
	lastName string,
	adminMode bool) error {

	if !adminMode {
		if user.IsLocked {
			return fmt.Errorf("account is locked and cannot be edited")
		}

		err := userdb.CheckUsername(username)

		if err != nil {
			return err
		}

		err = userdb.CheckName(firstName)

		if err != nil {
			return err
		}
	}

	_, err := mydb.db.Exec(SetInfoSql, username, firstName, lastName, user.PublicId)

	if err != nil {
		log.Debug().Msgf("%s", err)
		return fmt.Errorf("could not update user info")
	}

	return err
}

// func (mydb *mydb) SetEmail(publicId string, email string) error {
// 	address, err := mail.ParseAddress(email)

// 	if err != nil {
// 		return err
// 	}

// 	return mydb.SetEmailAddress(publicId, address)
// }

func (mydb *MySQLUserDB) SetEmailAddress(user *auth.AuthUser, address *mail.Address, adminMode bool) error {

	if !adminMode && user.IsLocked {
		return fmt.Errorf("account is locked and cannot be edited")
	}

	_, err := mydb.db.Exec(SetEmailSql, address.Address, user.PublicId)

	if err != nil {
		return fmt.Errorf("could not update email address")
	}

	return err
}

func (mydb *MySQLUserDB) SetUserRoles(user *auth.AuthUser, roles []string, adminMode bool) error {
	if !adminMode && user.IsLocked {
		return fmt.Errorf("account is locked and cannot be edited")
	}

	// remove existing roles,
	_, err := mydb.db.Exec(DeleteRolesSql, user.Id)

	if err != nil {
		return err
	}

	for _, role := range roles {
		err = mydb.AddRoleToUser(user, role, adminMode)

		if err != nil {
			return err
		}
	}

	return nil
}

func (mydb *MySQLUserDB) AddRoleToUser(user *auth.AuthUser, roleName string, adminMode bool) error {
	if !adminMode && user.IsLocked {
		return fmt.Errorf("account is locked and cannot be edited")
	}

	var role *auth.Role

	role, err := mydb.FindRoleByName(roleName)

	if err != nil {
		return err
	}

	_, err = mydb.db.Exec(InsertUserRoleSql, user.Id, role.Id)

	if err != nil {
		return err
	}

	return nil
}

func (mydb *MySQLUserDB) CreateApiKeyForUser(user *auth.AuthUser, adminMode bool) error {
	if !adminMode && user.IsLocked {
		return fmt.Errorf("account is locked and cannot be edited")
	}

	uuid, err := sys.Uuid()

	if err != nil {
		return err
	}

	_, err = mydb.db.Exec(InsertApiKeySql, user.Id, uuid)

	if err != nil {
		return err
	}

	return nil
}

// func (mydb *mydb) SetOtp(userId string, otp string) error {
// 	_, err := mydb.setOtpStmt.Exec(otp, userId)

// 	return err
// }

func (mydb *MySQLUserDB) CreateUserFromSignup(user *auth.UserBodyReq) (*auth.AuthUser, error) {
	email, err := mail.ParseAddress(user.Email)

	log.Debug().Msgf("aha %v", email)

	if err != nil {
		return nil, err
	}

	// The default username is email address unless a username is provided
	userName := email.Address

	if user.Username != "" {
		userName = user.Username
	}

	// assume email is not verified
	return mydb.CreateUser(userName, email, user.Password, user.FirstName, user.LastName, false)
}

// Gets the user info from the database and auto creates user if
// user does not exist since we Auth0 has authenticated them
func (mydb *MySQLUserDB) CreateUserFromOAuth2(name string, email *mail.Address) (*auth.AuthUser, error) {
	authUser, err := mydb.FindUserByEmail(email)

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
	return mydb.CreateUser(email.Address, email, "", firstName, lastName, true)

}

func (mydb *MySQLUserDB) CreateUser(userName string,
	email *mail.Address,
	password string,
	firstName string,
	lastName string,
	emailIsVerified bool) (*auth.AuthUser, error) {
	err := userdb.CheckPassword(password)

	if err != nil {
		return nil, err
	}

	// Check if user exists and if they do, check passwords match.
	// We don't care about errors because errors signify the user
	// doesn't exist so we can continue and make the user
	authUser, _ := mydb.FindUserByEmail(email)

	if authUser != nil {
		// user already exists so check if verified

		if authUser.EmailVerifiedAt > userdb.EmailNotVerifiedDate {
			return nil, fmt.Errorf("user already registered: please sign up with a different email address")
		}

		// if user is not verified, update the password since we assume
		// rightful owner of email address will keep trying until verified
		// this is to stop people blocking creation of accounts by just
		// signing up with email addresses they have no intention of
		// verifying
		err := mydb.SetPassword(authUser, password)

		if err != nil {
			return nil, fmt.Errorf("user already registered: please sign up with another email address")
		}

		// ensure user is the updated version
		return mydb.FindUserById(authUser.Id)
	}

	// try to create user if user does not exist

	// Create a publicId for the user id
	publicId, err := sys.Uuid() // sys.NanoId()

	if err != nil {
		return nil, fmt.Errorf("could not create uuid for user")
	}

	hash := ""

	// empty passwords indicate passwordless
	if password != "" {
		hash = auth.HashPassword(password)
	}

	// default to unverified i.e. if time is epoch (1970) assume
	// unverified
	emailVerifiedAt := userdb.EpochDate

	if emailIsVerified {
		emailVerifiedAt = time.Now().Format(time.RFC3339)
	}

	log.Debug().Msgf("%s %s %s", publicId, email.Address, emailVerifiedAt)

	_, err = mydb.db.Exec(
		InsertUserSql,
		publicId,
		userName,
		email.Address,
		hash,
		firstName,
		lastName,
		emailVerifiedAt,
	)

	if err != nil {
		log.Debug().Msgf("error making person %s %v", publicId, err)
		return nil, err
	}

	// Call function again to get the user details
	authUser, err = mydb.FindUserByPublicId(publicId)

	if err != nil {
		return nil, err
	}

	// Give user standard role and ability to login
	err = mydb.AddRoleToUser(authUser, auth.RoleUser, true)

	if err != nil {
		return nil, err
	}

	err = mydb.AddRoleToUser(authUser, auth.RoleSignin, true)

	if err != nil {
		return nil, err
	}

	err = mydb.CreateApiKeyForUser(authUser, true)

	if err != nil {
		return nil, err
	}

	// return the updated version
	return mydb.FindUserById(authUser.Id)
}
