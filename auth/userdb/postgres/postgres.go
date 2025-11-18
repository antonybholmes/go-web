package postgres

import (
	"context"
	"fmt"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/antonybholmes/go-sys"
	"github.com/antonybholmes/go-web/auth"
	"github.com/antonybholmes/go-web/auth/userdb"

	"github.com/antonybholmes/go-sys/log"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresUserDB struct {
	db  *pgxpool.Pool
	ctx context.Context
}

const (

	// postgres version
	SelectUsersSql string = `SELECT 
		id,
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

	UsersSql string = SelectUsersSql + ` ORDER BY first_name, last_name, email LIMIT $1 OFFSET $2`

	FindUserByIdSql string = SelectUsersSql + ` WHERE users.id = $1`

	//FindUserByPublicIdSql string = SelectUsersSql + ` WHERE users.public_id = $1`

	FindUserByEmailSql string = SelectUsersSql + ` WHERE users.email = $1`

	FindUserByUsernameSql string = SelectUsersSql + ` WHERE users.username = $1`

	FindUserByApiKeySql string = `SELECT 
		id, user_id, api_key
		FROM api_keys 
		WHERE api_key = $1`

	UsersApiKeysSql string = `SELECT 
		id, api_key
		FROM api_keys 
		WHERE user_id = $1
		ORDER BY api_key`

	RolesSql string = `SELECT 
		id, 
		name, 
		description
		FROM roles 
		ORDER BY roles.name`

	PermissionsSql string = `SELECT DISTINCT 
		permissions.id, 
		permissions.name, 
		permissions.description
		FROM users_roles, roles_permissions, permissions 
		WHERE users_roles.user_id = $1 AND roles_permissions.role_id = users_roles.role_id AND 
		permissions.id = roles_permissions.permission_id 
		ORDER BY permissions.name`

	// UserRolesSql string = `SELECT DISTINCT
	// roles.id,
	// roles.public_id,
	// roles.name,
	// roles.description
	// FROM users_roles, roles
	// WHERE users_roles.user_id = $1 AND roles.id = users_roles.role_id
	// ORDER BY roles.name`

	// UserRolesSql string = `SELECT DISTINCT
	// 	r.name as role,
	// 	p.name AS permission
	// 	FROM users u
	// 	JOIN user_groups ug ON u.id = ug.user_id
	// 	JOIN group_roles gr ON ug.group_id = gr.group_id
	// 	JOIN role_permissions rp ON gr.role_id = rp.role_id
	// 	JOIN roles r ON rp.role_id = r.id
	// 	JOIN permissions p ON rp.permission_id = p.id
	// 	WHERE u.id = $1
	// 	ORDER BY r.name, p.name`

	UserGroupsSql string = `SELECT DISTINCT
		g.id as group_id,
		g.name as group,
		r.id as role_id,
		r.name as role,
		p.id as permission_id,
		p.name as permission,
		res.id as resource_id,
		res.name as resource,
		a.id as action_id,
		a.name as action
		FROM users u
		JOIN user_groups ug ON u.id = ug.user_id
		JOIN group_roles gr ON ug.group_id = gr.group_id
		JOIN role_permissions rp ON gr.role_id = rp.role_id
		JOIN groups g ON gr.group_id = g.id
		JOIN roles r ON rp.role_id = r.id
		JOIN permissions p ON rp.permission_id = p.id
		JOIN resources res ON p.resource_id = res.id
		JOIN actions a ON p.action_id = a.id
		WHERE u.id = $1
		ORDER BY g.name, r.name, res.name, a.name`

	UserRolesSql string = `SELECT DISTINCT
		r.id as role_id,
		r.name as role,
		p.id as permission_id,
		p.name as permission,
		res.id as resource_id,
		res.name as resource,
		a.id as action_id,
		a.name as action
		FROM users u
		JOIN user_groups ug ON u.id = ug.user_id
		JOIN group_roles gr ON ug.group_id = gr.group_id
		JOIN role_permissions rp ON gr.role_id = rp.role_id
		JOIN roles r ON rp.role_id = r.id
		JOIN permissions p ON rp.permission_id = p.id
		JOIN resources res ON p.resource_id = res.id
		JOIN actions a ON p.action_id = a.id
		WHERE u.id = $1
		ORDER BY r.name, res.name, a.name`

	InsertUserSql = `INSERT INTO users 
		(username, email, password, first_name, last_name, email_verified_at) 
		VALUES ($1, $2, $3, $4, $5, $6) 
		ON CONFLICT DO NOTHING`

	DeleteUserGroupsSql = "DELETE FROM user_groups WHERE user_id = $1"
	InsertUserGroupSql  = "INSERT INTO user_groups (user_id, group_id) VALUES($1, $2) ON CONFLICT DO NOTHING"

	InsertApiKeySql = "INSERT INTO api_keys (user_id, api_key) VALUES($1, $2) ON CONFLICT DO NOTHING"

	SetEmailVerifiedSql = `UPDATE users SET email_verified_at = now() WHERE users.id = $1`
	SetPasswordSql      = `UPDATE users SET password = $1 WHERE users.id = $2`
	SetUsernameSql      = `UPDATE users SET username = $1 WHERE users.id = $2`

	SetInfoSql  = `UPDATE users SET username = $1, first_name = $2, last_name = $3 WHERE users.id = $4`
	SetEmailSql = `UPDATE users SET email = $1 WHERE users.id = $2`

	DeleteUserSql = `DELETE FROM users WHERE id = $1`

	CountUsersSql = `SELECT COUNT(ID) FROM users`

	RoleSql = `SELECT 
		roles.id, 
		roles.name,
		roles.description 
		FROM roles`

	GroupsSql = `SELECT 
		groups.id, 
		groups.name,
		groups.description 
		FROM groups
		ORDER BY groups.name`

	GroupSql = `SELECT 
		groups.id,
		groups.name,
		groups.description 
		FROM groups
		WHERE groups.id = $1 OR groups.name = $1`
)

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

func (pgdb *PostgresUserDB) Db() *pgxpool.Pool {
	return pgdb.db
}

func (pgdb *PostgresUserDB) NumUsers() (uint, error) {

	var n uint

	err := pgdb.db.QueryRow(pgdb.ctx, CountUsersSql).Scan(&n)

	if err != nil {
		return 0, err
	}

	return n, nil
}

func (pgdb *PostgresUserDB) Users(records uint, offset uint) ([]*auth.AuthUser, error) {
	log.Debug().Msgf("users %d %d %s", records, offset, UsersSql)

	rows, err := pgdb.db.Query(pgdb.ctx, UsersSql, records, offset)

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
			Groups:  make([]*auth.RBACGroup, 0, 5),
			ApiKeys: make([]string, 0, 5),
		}

		err := rows.Scan(&authUser.Id,
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

		err = pgdb.AddGroupsToUser(&authUser)

		if err != nil {
			return nil, err
		}

		authUsers = append(authUsers, &authUser)
	}

	return authUsers, nil
}

func (pgdb *PostgresUserDB) DeleteUser(id string) error {

	authUser, err := pgdb.FindUserById(id)

	if err != nil {
		return err
	}

	//roles, err := pgdb.UserRoleList(authUser)

	// if err != nil {
	// 	return err
	// }

	if auth.UserHasAdminRole(authUser) {
		return fmt.Errorf("cannot delete admin account")
	}

	_, err = pgdb.db.Exec(pgdb.ctx, DeleteUserSql, id)

	if err != nil {
		return err
	}

	return nil
}

func (pgdb *PostgresUserDB) FindUserByEmail(email *mail.Address) (*auth.AuthUser, error) {
	return pgdb.findUser(email.Address, pgdb.db.QueryRow(pgdb.ctx, FindUserByEmailSql, email.Address))
}

func (pgdb *PostgresUserDB) FindUserByUsername(username string) (*auth.AuthUser, error) {

	if strings.Contains(username, "@") {
		email, err := mail.ParseAddress(username)

		if err != nil {
			return nil, err
		}

		return pgdb.FindUserByEmail(email)
	}

	err := userdb.CheckUsername(username)

	if err != nil {
		return nil, err
	}

	return pgdb.findUser(username, pgdb.db.QueryRow(pgdb.ctx, FindUserByUsernameSql, username))
}

func (pgdb *PostgresUserDB) FindUserById(id string) (*auth.AuthUser, error) {
	return pgdb.findUser(id, pgdb.db.QueryRow(pgdb.ctx, FindUserByIdSql, id))
}

// func (pgdb *PostgresUserDB) FindUserByPublicId(publicId string) (*auth.AuthUser, error) {
// 	return pgdb.findUser(publicId, pgdb.db.QueryRow(pgdb.ctx, FindUserByPublicIdSql, publicId))
// }

// Helper function used by various FindUser methods. Converts a db row to an AuthUser
func (pgdb *PostgresUserDB) findUser(id string, row pgx.Row) (*auth.AuthUser, error) {

	var authUser auth.AuthUser
	//var updatedAt int64

	err := row.Scan(&authUser.Id,
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
		return nil, userdb.NewUserNotFoundError(id)
	}

	//authUser.UpdatedAt = time.Duration(updatedAt)

	err = pgdb.AddGroupsToUser(&authUser)

	if err != nil {
		log.Error().Msgf("error adding roles to user %s %v", authUser.Id, err)
		return nil, err
	}

	err = pgdb.AddApiKeysToUser(&authUser)

	if err != nil {
		return nil, err
	}

	return &authUser, nil
}

func (pgdb *PostgresUserDB) FindUserByApiKey(key string) (*auth.AuthUser, error) {

	if !sys.IsValidUUID(key) {
		return nil, fmt.Errorf("api key is not in valid format")
	}

	var id uint
	var userId string
	//var createdAt int64

	err := pgdb.db.QueryRow(pgdb.ctx, FindUserByApiKeySql, key).Scan(&id,
		&userId, &key)

	if err != nil {
		return nil, err
	}

	return pgdb.FindUserById(userId)
}

func (pgdb *PostgresUserDB) AddGroupsToUser(authUser *auth.AuthUser) error {

	groups, err := pgdb.UserGroups(authUser)

	//log.Debug().Msgf("add groups to user %s: %v", authUser.Username, groups)

	if err != nil {
		return err //fmt.Errorf("there was an error with the database query")
	}

	authUser.Groups = append(authUser.Groups, groups...)

	return nil
}

// func (pgdb *PostgresUserDB) UserRoleList(user *auth.AuthUser) ([]auth.RolePermissions, error) {

// 	roles, err := pgdb.UserRoles(user)

// 	if err != nil {
// 		return nil, err
// 	}

// 	ret := make([]string, len(roles))

// 	for ri, role := range roles {
// 		ret[ri] = role.Name
// 	}

// 	return ret, nil

// }

func (pgdb *PostgresUserDB) AddApiKeysToUser(authUser *auth.AuthUser) error {

	keys, err := pgdb.UserApiKeys(authUser)

	if err != nil {
		return err //fmt.Errorf("there was an error with the database query")
	}

	authUser.ApiKeys = keys

	return nil
}

func (pgdb *PostgresUserDB) UserApiKeys(user *auth.AuthUser) ([]string, error) {

	rows, err := pgdb.db.Query(pgdb.ctx, UsersApiKeysSql, user.Id)

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

func (pgdb *PostgresUserDB) UserGroups(user *auth.AuthUser) ([]*auth.RBACGroup, error) {

	log.Debug().Msgf("getting user groups for %s", user.Id)

	rows, err := pgdb.db.Query(pgdb.ctx, UserGroupsSql, user.Id)

	if err != nil {
		return nil, fmt.Errorf("user roles not found")
	}

	defer rows.Close()

	groups := make([]*auth.RBACGroup, 0, 10)

	var currentGroup *auth.RBACGroup = nil
	var currentRole *auth.RBACRole = nil
	var currentPermission *auth.RBACPermission = nil

	var groupId string
	var group string
	var roleId string
	var role string
	var permissionId string
	var permission string
	var resourceId string
	var resource string
	var actionId string
	var action string

	for rows.Next() {

		err := rows.Scan(
			&groupId,
			&group,
			&roleId,
			&role,
			&permissionId,
			&permission,
			&resourceId,
			&resource,
			&actionId,
			&action)

		if err != nil {
			log.Error().Msgf("error scanning user groups %v", err)
			return nil, fmt.Errorf("user roles not found: %v", err)
		}

		if currentGroup == nil || currentGroup.Name != group {
			currentGroup = &auth.RBACGroup{
				RBACEntity: auth.RBACEntity{
					Id:   groupId,
					Name: group,
				},
				Roles: make([]*auth.RBACRole, 0, 10)}
			groups = append(groups, currentGroup)
		}

		if currentRole == nil || currentRole.Name != role {
			currentRole = &auth.RBACRole{
				RBACEntity: auth.RBACEntity{
					Id:   roleId,
					Name: role,
				},
				Permissions: make([]*auth.RBACPermission, 0, 10),
			}

			currentGroup.Roles = append(currentGroup.Roles, currentRole)
		}

		currentPermission = &auth.RBACPermission{

			RBACEntity: auth.RBACEntity{
				Id:   permissionId,
				Name: permission,
			},
			Resource: resource,
			Action:   action,
		}

		currentRole.Permissions = append(currentRole.Permissions, currentPermission)

	}

	return groups, nil
}

// func (pgdb *PostgresUserDB) PermissionList(user *auth.AuthUser) ([]string, error) {

// 	permissions, err := pgdb.Permissions(user)

// 	if err != nil {
// 		return nil, err
// 	}

// 	ret := make([]string, len(permissions))

// 	for pi, permission := range permissions {
// 		ret[pi] = permission.Name
// 	}

// 	return ret, nil

// }

// func (pgdb *pgdb) Query(pgdb.ctx,query string, args ...any) (*sql.Rows, error) {
// 	return pgdb.db.Query(pgdb.ctx,query, args...)
// }

// func (pgdb *pgdb) QueryRow(pgdb.ctx,query string, args ...any) *sql.Row {
// 	db, err := sql.Open("sqlite3", pgdb.file) //not clear on what is needed for the user and password

// 	if err != nil {
// 		return nil, err
// 	}

// 	defer db.Close()
// 	return pgdb.db.QueryRow(pgdb.ctx,query, args...)
// }

func (pgdb *PostgresUserDB) Groups() ([]*auth.RBACGroup, error) {

	rows, err := pgdb.db.Query(pgdb.ctx, GroupsSql)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var groups []*auth.RBACGroup

	for rows.Next() {
		var group auth.RBACGroup
		err := rows.Scan(&group.Id,
			&group.Name,
			&group.Description)

		if err != nil {
			return nil, err
		}
		groups = append(groups, &group)

	}

	return groups, nil
}

func (pgdb *PostgresUserDB) Roles() ([]*auth.RBACRole, error) {

	rows, err := pgdb.db.Query(pgdb.ctx, RolesSql)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var roles []*auth.RBACRole

	for rows.Next() {
		var role auth.RBACRole
		err := rows.Scan(&role.Id,
			&role.Name,
			&role.Description)

		if err != nil {
			return nil, err
		}

		roles = append(roles, &role)
	}

	return roles, nil
}

func (pgdb *PostgresUserDB) FindRoleByName(name string) (*auth.RBACRole, error) {

	var role auth.RBACRole

	err := pgdb.db.QueryRow(pgdb.ctx, RoleSql, name).Scan(&role.Id,
		&role.Name,
		&role.Description)

	if err != nil {
		return nil, userdb.NewAccountError(fmt.Sprintf("%s role not found", name))
	}

	return &role, nil
}

// FindGroupByName finds group by public id or name
func (pgdb *PostgresUserDB) FindGroup(name string) (*auth.RBACGroup, error) {

	var group auth.RBACGroup

	err := pgdb.db.QueryRow(pgdb.ctx, GroupSql, name).Scan(&group.Id,
		&group.Name,
		&group.Description)

	//log.Debug().Msgf("find group %v err %v", group, err)

	if err != nil {
		return nil, userdb.NewAccountError(fmt.Sprintf("%s group not found", name))
	}

	return &group, nil
}

// func (pgdb *PostgresUserDB) Permissions(user *auth.AuthUser) ([]*auth.Permission, error) {

// 	rows, err := pgdb.db.Query(pgdb.ctx, PermissionsSql, user.Id)

// 	if err != nil {
// 		return nil, err
// 	}

// 	defer rows.Close()

// 	permissions := make([]*auth.Permission, 0, 10)

// 	for rows.Next() {
// 		var permission auth.Permission

// 		err := rows.Scan(&permission.Id, &permission.PublicId, &permission.Name, &permission.Description)

// 		if err != nil {
// 			return nil, err
// 		}

// 		permissions = append(permissions, &permission)
// 	}

// 	return permissions, nil
// }

func (pgdb *PostgresUserDB) SetIsVerified(userId string) error {

	_, err := pgdb.db.Exec(pgdb.ctx, SetEmailVerifiedSql, userId)

	if err != nil {
		return userdb.NewAccountError("could not verify email address")
	}

	// _, err = pgdb.setOtpStmt.Exec(pgdb.ctx,"", userId)

	// if err != nil {
	// 	return false
	// }

	return nil
}

func (pgdb *PostgresUserDB) SetPassword(user *auth.AuthUser, password string) error {
	if user.IsLocked {
		return userdb.NewPasswordError("account is locked and cannot be edited")
	}

	var err error

	err = userdb.CheckPassword(password)

	if err != nil {
		return err
	}

	hash := auth.HashPassword(password)

	_, err = pgdb.db.Exec(pgdb.ctx, SetPasswordSql, hash, user.Id)

	if err != nil {
		return userdb.NewPasswordError("could not update password")
	}

	return err
}

// func (pgdb *pgdb) SetUsername(publicId string, username string) error {

// 	err := CheckUsername(username)

// 	if err != nil {
// 		return err
// 	}

// 	db, err := pgdb.NewConn()

// 	if err != nil {
// 		return err
// 	}

// 	defer db.Close()

// 	_, err = db.Exec(pgdb.ctx,SET_USERNAME_SQL, username, publicId)

// 	if err != nil {
// 		return fmt.Errorf("could not update username")
// 	}

// 	return err
// }

// func (pgdb *pgdb) SetName(publicId string, firstName string, lastName string) error {
// 	err := CheckName(firstName)

// 	if err != nil {
// 		return err
// 	}

// 	err = CheckName(lastName)

// 	if err != nil {
// 		return err
// 	}

// 	db, err := pgdb.NewConn()

// 	if err != nil {
// 		return err
// 	}

// 	defer db.Close()

// 	_, err = db.Exec(pgdb.ctx,SET_NAME_SQL, publicId, firstName, lastName)

// 	if err != nil {
// 		return fmt.Errorf("could not update name")
// 	}

// 	return err
// }

func (pgdb *PostgresUserDB) SetUserInfo(user *auth.AuthUser,
	username string,
	firstName string,
	lastName string,
	adminMode bool) error {

	if !adminMode {
		if user.IsLocked {
			return userdb.NewAccountError("account is locked and cannot be edited")
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

	_, err := pgdb.db.Exec(pgdb.ctx, SetInfoSql, username, firstName, lastName, user.Id)

	if err != nil {
		return userdb.NewAccountError("could not update user info")
	}

	return nil
}

// func (pgdb *pgdb) SetEmail(publicId string, email string) error {
// 	address, err := mail.ParseAddress(email)

// 	if err != nil {
// 		return err
// 	}

// 	return pgdb.SetEmailAddress(publicId, address)
// }

func (pgdb *PostgresUserDB) SetEmailAddress(user *auth.AuthUser, address *mail.Address, adminMode bool) error {

	if !adminMode && user.IsLocked {
		return userdb.NewAccountError("account is locked and cannot be edited")
	}

	_, err := pgdb.db.Exec(pgdb.ctx, SetEmailSql, address.Address, user.Id)

	if err != nil {
		return userdb.NewAccountError("could not update email address")
	}

	return nil
}

func (pgdb *PostgresUserDB) SetUserGroups(user *auth.AuthUser, groups []string, adminMode bool) error {
	if !adminMode && user.IsLocked {
		return userdb.NewAccountError("account is locked and cannot be edited")
	}

	// remove existing roles,
	_, err := pgdb.db.Exec(pgdb.ctx, DeleteUserGroupsSql, user.Id)

	if err != nil {
		return err
	}

	for _, group := range groups {
		err = pgdb.AddUserToGroup(user, group, adminMode)

		if err != nil {
			return err
		}
	}

	return nil
}

func (pgdb *PostgresUserDB) AddUserToGroup(user *auth.AuthUser, group string, adminMode bool) error {
	if !adminMode && user.IsLocked {
		return userdb.NewAccountError("account is locked and cannot be edited")
	}

	g, err := pgdb.FindGroup(group)

	if err != nil {
		return err
	}

	log.Debug().Msgf("add user to group %s %s %s", group, user.Id, g.Id)

	_, err = pgdb.db.Exec(pgdb.ctx, InsertUserGroupSql, user.Id, g.Id)

	if err != nil {
		log.Debug().Msgf("error adding user to group %v", err)
		return userdb.NewAccountError("could not add user to group")
	}

	return nil
}

func (pgdb *PostgresUserDB) CreateApiKeyForUser(user *auth.AuthUser, adminMode bool) error {
	if !adminMode && user.IsLocked {
		return fmt.Errorf("account is locked and cannot be edited")
	}

	uuid, err := sys.Uuidv7()

	if err != nil {
		return err
	}

	_, err = pgdb.db.Exec(pgdb.ctx, InsertApiKeySql, user.Id, uuid)

	if err != nil {
		return err
	}

	return nil
}

// func (pgdb *pgdb) SetOtp(userId string, otp string) error {
// 	_, err := pgdb.setOtpStmt.Exec(pgdb.ctx,otp, userId)

// 	return err
// }

func (pgdb *PostgresUserDB) CreateUserFromSignup(user *auth.UserBodyReq) (*auth.AuthUser, error) {
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
	return pgdb.CreateUser(userName, email, user.Password, user.FirstName, user.LastName, false)
}

// Gets the user info from the database and auto creates user if
// user does not exist since we Auth0 has authenticated them
func (pgdb *PostgresUserDB) CreateUserFromOAuth2(name string, email *mail.Address) (*auth.AuthUser, error) {
	authUser, err := pgdb.FindUserByEmail(email)

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
	return pgdb.CreateUser(email.Address, email, "", firstName, lastName, true)

}

func (pgdb *PostgresUserDB) CreateUser(userName string,
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
	authUser, _ := pgdb.FindUserByEmail(email)

	log.Debug().Msgf("create user found %v %s", authUser, email)

	if authUser != nil {
		// user already exists so check if verified

		if authUser.EmailVerifiedAt > userdb.EmailNotVerifiedDate {
			return nil, userdb.NewAccountError("user already registered: please sign up with a different email address")
		}

		// if user is not verified, update the password since we assume
		// rightful owner of email address will keep trying until verified
		// this is to stop people blocking creation of accounts by just
		// signing up with email addresses they have no intention of
		// verifying
		err := pgdb.SetPassword(authUser, password)

		if err != nil {
			return nil, userdb.NewAccountError("user already registered: please sign up with another email address")
		}

		// ensure user is the updated version
		return pgdb.FindUserById(authUser.Id)
	}

	// try to create user if user does not exist

	// Create a publicId for the user id
	//publicId, err := sys.Uuidv7() // sys.NanoId()

	//if err != nil {
	//	return nil, userdb.NewAccountError("could not create uuid for user")
	//}

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

	log.Debug().Msgf("%s %s", email.Address, emailVerifiedAt)

	_, err = pgdb.db.Exec(pgdb.ctx,
		InsertUserSql,
		userName,
		email.Address,
		hash,
		firstName,
		lastName,
		emailVerifiedAt,
	)

	if err != nil {
		log.Debug().Msgf("error making person %s %v", email.Address, err)
		return nil, err
	}

	// Call function again to get the user details
	authUser, err = pgdb.FindUserByEmail(email)

	if err != nil {
		log.Debug().Msgf("find by error user %v", err)
		return nil, err
	}

	log.Debug().Msgf("created user %v", authUser)

	// Give user standard role and ability to login
	err = pgdb.AddUserToGroup(authUser, auth.GroupLogin, true)

	if err != nil {
		log.Debug().Msgf("error adding user to group %s %v", email.Address, err)
		return nil, err
	}

	// err = pgdb.AddUserToGroup(authUser, auth.RoleLogin, true)

	// if err != nil {
	// 	return nil, err
	// }

	err = pgdb.CreateApiKeyForUser(authUser, true)

	if err != nil {
		return nil, err
	}

	// return the updated version
	return pgdb.FindUserById(authUser.Id)
}
