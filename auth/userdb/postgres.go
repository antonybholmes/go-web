package userdb

import (
	"context"
	"fmt"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/antonybholmes/go-sys"
	"github.com/antonybholmes/go-web/auth"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

type PostgresUserDB struct {
	db  *pgxpool.Pool
	ctx context.Context
}

func NewPostgresUserDB() *PostgresUserDB {
	//db := sys.Must(sql.Open("sqlite3", file))
	ctx := context.Background()

	log.Debug().Msgf("conn %s", os.Getenv("DATABASE_URL"))

	db := sys.Must(pgxpool.New(ctx, os.Getenv("DATABASE_URL")))

	log.Debug().Msgf("Connected!")

	return &PostgresUserDB{
		db:  db,
		ctx: ctx,
	}
}

func (userdb *PostgresUserDB) Db() *pgxpool.Pool {
	return userdb.db
}

func (userdb *PostgresUserDB) NumUsers() (uint, error) {

	var n uint

	err := userdb.db.QueryRow(userdb.ctx, CountUsersSql).Scan(&n)

	if err != nil {
		return 0, err
	}

	return n, nil
}

func (userdb *PostgresUserDB) Users(records uint, offset uint) ([]*auth.AuthUser, error) {
	log.Debug().Msgf("users %d %d %s", records, offset, UsersSql)

	rows, err := userdb.db.Query(userdb.ctx, UsersSql, records, offset)

	if err != nil {
		log.Debug().Msgf("users2 %d %d %s", records, offset, UsersSql)
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

		err = userdb.AddRolesToUser(&authUser)

		if err != nil {
			return nil, err
		}

		authUsers = append(authUsers, &authUser)
	}

	return authUsers, nil
}

func (userdb *PostgresUserDB) DeleteUser(publicId string) error {

	authUser, err := userdb.FindUserByPublicId(publicId)

	if err != nil {
		return err
	}

	roles, err := userdb.UserRoleList(authUser)

	if err != nil {
		return err
	}

	claim := auth.MakeClaim(roles)

	if strings.Contains(claim, auth.RoleSuper) {
		return fmt.Errorf("cannot delete superuser account")
	}

	_, err = userdb.db.Exec(userdb.ctx, DeleteUserSql, publicId)

	if err != nil {
		return err
	}

	return nil
}

func (userdb *PostgresUserDB) FindUserByEmail(email *mail.Address) (*auth.AuthUser, error) {
	return userdb.findUser(userdb.db.QueryRow(userdb.ctx, FindUserByEmailSql, email.Address))
}

func (userdb *PostgresUserDB) FindUserByUsername(username string) (*auth.AuthUser, error) {

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

	return userdb.findUser(userdb.db.QueryRow(userdb.ctx, FindUserByUsernameSql, username))
}

func (userdb *PostgresUserDB) FindUserById(id uint) (*auth.AuthUser, error) {
	return userdb.findUser(userdb.db.QueryRow(userdb.ctx, FindUserByIdSql, id))
}

func (userdb *PostgresUserDB) FindUserByPublicId(publicId string) (*auth.AuthUser, error) {
	return userdb.findUser(userdb.db.QueryRow(userdb.ctx, FindUserByPublicIdSql, publicId))
}

func (userdb *PostgresUserDB) findUser(row pgx.Row) (*auth.AuthUser, error) {

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

func (userdb *PostgresUserDB) FindUserByApiKey(key string) (*auth.AuthUser, error) {

	if !sys.IsValidUUID(key) {
		return nil, fmt.Errorf("api key is not in valid format")
	}

	var id uint
	var userId uint
	//var createdAt int64

	err := userdb.db.QueryRow(userdb.ctx, FindUserByApiKeySql, key).Scan(&id,
		&userId, &key)

	if err != nil {
		return nil, err
	}

	return userdb.FindUserById(userId)
}

func (userdb *PostgresUserDB) AddRolesToUser(authUser *auth.AuthUser) error {

	roles, err := userdb.UserRoleList(authUser)

	if err != nil {
		return err //fmt.Errorf("there was an error with the database query")
	}

	authUser.Roles = append(authUser.Roles, roles...)

	return nil
}

func (userdb *PostgresUserDB) UserRoleList(user *auth.AuthUser) ([]string, error) {

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

func (userdb *PostgresUserDB) AddApiKeysToUser(authUser *auth.AuthUser) error {

	keys, err := userdb.UserApiKeys(authUser)

	if err != nil {
		return err //fmt.Errorf("there was an error with the database query")
	}

	authUser.ApiKeys = keys

	return nil
}

func (userdb *PostgresUserDB) UserApiKeys(user *auth.AuthUser) ([]string, error) {

	rows, err := userdb.db.Query(userdb.ctx, UsersApiKeysSql, user.Id)

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

func (userdb *PostgresUserDB) UserRoles(user *auth.AuthUser) ([]*auth.Role, error) {

	rows, err := userdb.db.Query(userdb.ctx, UserRolesSql, user.Id)

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

func (userdb *PostgresUserDB) PermissionList(user *auth.AuthUser) ([]string, error) {

	permissions, err := userdb.Permissions(user)

	if err != nil {
		return nil, err
	}

	ret := make([]string, len(permissions))

	for pi, permission := range permissions {
		ret[pi] = permission.Name
	}

	return ret, nil

}

// func (userdb *UserDb) Query(userdb.ctx,query string, args ...any) (*sql.Rows, error) {
// 	return userdb.db.Query(userdb.ctx,query, args...)
// }

// func (userdb *UserDb) QueryRow(userdb.ctx,query string, args ...any) *sql.Row {
// 	db, err := sql.Open("sqlite3", userdb.file) //not clear on what is needed for the user and password

// 	if err != nil {
// 		return nil, err
// 	}

// 	defer db.Close()
// 	return userdb.db.QueryRow(userdb.ctx,query, args...)
// }

func (userdb *PostgresUserDB) Roles() ([]*auth.Role, error) {

	rows, err := userdb.db.Query(userdb.ctx, RolesSql)

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

func (userdb *PostgresUserDB) FindRoleByName(name string) (*auth.Role, error) {

	var role auth.Role

	err := userdb.db.QueryRow(userdb.ctx, RoleSql, name).Scan(&role.Id,
		&role.PublicId,
		&role.Name,
		&role.Description)

	if err != nil {
		return nil, err
	}

	return &role, err
}

func (userdb *PostgresUserDB) Permissions(user *auth.AuthUser) ([]*auth.Permission, error) {

	rows, err := userdb.db.Query(userdb.ctx, PermissionsSql, user.Id)

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

func (userdb *PostgresUserDB) SetIsVerified(userId string) error {

	_, err := userdb.db.Exec(userdb.ctx, SetEmailVerifiedSql, userId)

	if err != nil {
		return err
	}

	// _, err = userdb.setOtpStmt.Exec(userdb.ctx,"", userId)

	// if err != nil {
	// 	return false
	// }

	return nil
}

func (userdb *PostgresUserDB) SetPassword(user *auth.AuthUser, password string) error {
	if user.IsLocked {
		return fmt.Errorf("account is locked and cannot be edited")
	}

	var err error

	err = CheckPassword(password)

	if err != nil {
		return err
	}

	hash := auth.HashPassword(password)

	_, err = userdb.db.Exec(userdb.ctx, SetPasswordSql, hash, user.PublicId)

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

// 	_, err = db.Exec(userdb.ctx,SET_USERNAME_SQL, username, publicId)

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

// 	_, err = db.Exec(userdb.ctx,SET_NAME_SQL, publicId, firstName, lastName)

// 	if err != nil {
// 		return fmt.Errorf("could not update name")
// 	}

// 	return err
// }

func (userdb *PostgresUserDB) SetUserInfo(user *auth.AuthUser,
	username string,
	firstName string,
	lastName string,
	adminMode bool) error {

	if !adminMode {
		if user.IsLocked {
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
	}

	_, err := userdb.db.Exec(userdb.ctx, SetInfoSql, username, firstName, lastName, user.PublicId)

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

func (userdb *PostgresUserDB) SetEmailAddress(user *auth.AuthUser, address *mail.Address, adminMode bool) error {

	if !adminMode && user.IsLocked {
		return fmt.Errorf("account is locked and cannot be edited")
	}

	_, err := userdb.db.Exec(userdb.ctx, SetEmailSql, address.Address, user.PublicId)

	if err != nil {
		return fmt.Errorf("could not update email address")
	}

	return err
}

func (userdb *PostgresUserDB) SetUserRoles(user *auth.AuthUser, roles []string, adminMode bool) error {
	if !adminMode && user.IsLocked {
		return fmt.Errorf("account is locked and cannot be edited")
	}

	// remove existing roles,
	_, err := userdb.db.Exec(userdb.ctx, DeleteRolesSql, user.Id)

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

func (userdb *PostgresUserDB) AddRoleToUser(user *auth.AuthUser, roleName string, adminMode bool) error {
	if !adminMode && user.IsLocked {
		return fmt.Errorf("account is locked and cannot be edited")
	}

	var role *auth.Role

	role, err := userdb.FindRoleByName(roleName)

	if err != nil {
		return err
	}

	_, err = userdb.db.Exec(userdb.ctx, InsertUserRoleSql, user.Id, role.Id)

	if err != nil {
		return err
	}

	return nil
}

func (userdb *PostgresUserDB) CreateApiKeyForUser(user *auth.AuthUser, adminMode bool) error {
	if !adminMode && user.IsLocked {
		return fmt.Errorf("account is locked and cannot be edited")
	}

	uuid, err := sys.Uuid()

	if err != nil {
		return err
	}

	_, err = userdb.db.Exec(userdb.ctx, InsertApiKeySql, user.Id, uuid)

	if err != nil {
		return err
	}

	return nil
}

// func (userdb *UserDb) SetOtp(userId string, otp string) error {
// 	_, err := userdb.setOtpStmt.Exec(userdb.ctx,otp, userId)

// 	return err
// }

func (userdb *PostgresUserDB) CreateUserFromSignup(user *auth.UserBodyReq) (*auth.AuthUser, error) {
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
	return userdb.CreateUser(userName, email, user.Password, user.FirstName, user.LastName, false)
}

// Gets the user info from the database and auto creates user if
// user does not exist since we Auth0 has authenticated them
func (userdb *PostgresUserDB) CreateUserFromOAuth2(name string, email *mail.Address) (*auth.AuthUser, error) {
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

func (userdb *PostgresUserDB) CreateUser(userName string,
	email *mail.Address,
	password string,
	firstName string,
	lastName string,
	emailIsVerified bool) (*auth.AuthUser, error) {
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

		if authUser.EmailVerifiedAt > EmailNotVerifiedDate {
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
	emailVerifiedAt := EpochDate

	if emailIsVerified {
		emailVerifiedAt = time.Now().Format(time.RFC3339)
	}

	log.Debug().Msgf("%s %s %s", publicId, email.Address, emailVerifiedAt)

	_, err = userdb.db.Exec(userdb.ctx,
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
	authUser, err = userdb.FindUserByPublicId(publicId)

	if err != nil {
		return nil, err
	}

	// Give user standard role and ability to login
	err = userdb.AddRoleToUser(authUser, auth.RoleUser, true)

	if err != nil {
		return nil, err
	}

	err = userdb.AddRoleToUser(authUser, auth.RoleSignin, true)

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
