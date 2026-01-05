package postgres

import (
	"context"
	"errors"
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
	SelectUsersSql = `SELECT 
		id,
		name, 
		username, 
		email, 
		is_locked, 
		password, 
		email_verified_at, 
		created_at, 
		updated_at
		FROM users
		`

	UsersSql = SelectUsersSql + ` ORDER BY name, email LIMIT @limit OFFSET @offset`

	FindUserByIdSql = SelectUsersSql + ` WHERE users.id = @id::uuid`

	FindUserByEmailSql = SelectUsersSql + ` WHERE users.email = @email`

	FindUserByUsernameSql = SelectUsersSql + ` WHERE users.username = @username`

	FindUserByApiKeySql = `SELECT 
		id, user_id, api_key
		FROM api_keys 
		WHERE api_key = @api_key`

	UserApiKeysSql = `SELECT 
		id, api_key
		FROM api_keys 
		WHERE user_id = @id::uuid
		ORDER BY api_key`

	UserPublicKeysSql = `SELECT 
		id, name, key
		FROM public_keys 
		WHERE user_id = @id::uuid
		ORDER BY name, key`

	RolesSql = `SELECT 
		id, 
		name, 
		description
		FROM roles 
		ORDER BY roles.name`

	// PermissionsSql = `SELECT DISTINCT
	// 	permissions.id,
	// 	permissions.name,
	// 	permissions.description
	// 	FROM users_roles, roles_permissions, permissions
	// 	WHERE users_roles.user_id = @id::uuid AND roles_permissions.role_id = users_roles.role_id AND
	// 	permissions.id = roles_permissions.permission_id
	// 	ORDER BY permissions.name`

	// UserRolesSql   = `SELECT DISTINCT
	// roles.id,
	// roles.public_id,
	// roles.name,
	// roles.description
	// FROM users_roles, roles
	// WHERE users_roles.user_id = $1 AND roles.id = users_roles.role_id
	// ORDER BY roles.name`

	// UserRolesSql   = `SELECT DISTINCT
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

	UserGroupsSql = `SELECT DISTINCT
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
		WHERE u.id = @id::uuid
		ORDER BY g.name, r.name, res.name, a.name`

	// UserRolesSql = `SELECT DISTINCT
	// 	r.id as role_id,
	// 	r.name as role,
	// 	p.id as permission_id,
	// 	p.name as permission,
	// 	res.id as resource_id,
	// 	res.name as resource,
	// 	a.id as action_id,
	// 	a.name as action
	// 	FROM users u
	// 	JOIN user_groups ug ON u.id = ug.user_id
	// 	JOIN group_roles gr ON ug.group_id = gr.group_id
	// 	JOIN role_permissions rp ON gr.role_id = rp.role_id
	// 	JOIN roles r ON rp.role_id = r.id
	// 	JOIN permissions p ON rp.permission_id = p.id
	// 	JOIN resources res ON p.resource_id = res.id
	// 	JOIN actions a ON p.action_id = a.id
	// 	WHERE u.id = @id::uuid
	// 	ORDER BY r.name, res.name, a.name`

	InsertUserSql = `INSERT INTO users 
		(username, email, password, name, email_verified_at) 
		VALUES (@username, @email, @password, @name, @email_verified_at) 
		ON CONFLICT DO NOTHING`

	DeleteUserGroupsSql = "DELETE FROM user_groups WHERE user_id = @id::uuid"
	InsertUserGroupSql  = "INSERT INTO user_groups (user_id, group_id) VALUES(@user_id, @group_id) ON CONFLICT DO NOTHING"

	InsertApiKeySql = "INSERT INTO api_keys (user_id, api_key) VALUES(@user_id, @api_key) ON CONFLICT DO NOTHING"

	SetEmailVerifiedSql = `UPDATE users SET email_verified_at = @time WHERE users.id = @id::uuid`
	SetPasswordSql      = `UPDATE users SET password = @password WHERE users.id = @id::uuid`
	SetUsernameSql      = `UPDATE users SET username = @username WHERE users.id = @id::uuid`

	SetInfoSql  = `UPDATE users SET username = @username, name = @name WHERE users.id = @id::uuid`
	SetEmailSql = `UPDATE users SET email = @email WHERE users.id = @id::uuid`

	DeleteUserSql = `DELETE FROM users WHERE id = @id::uuid`

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

	FindGroupByIdSql = `SELECT 
		groups.id,
		groups.name,
		groups.description 
		FROM groups
		WHERE groups.id = @id::uuid`

	FindGroupByNameSql = `SELECT 
		groups.id,
		groups.name,
		groups.description 
		FROM groups
		WHERE groups.name = @name`

	InsertAuthProviderSql     = "INSERT INTO auth_providers (name) VALUES(@name) ON CONFLICT DO NOTHING"
	FindAuthProviderByNameSql = "SELECT id, name FROM auth_providers WHERE name = @name"

	InsertUserAuthProviderSql = "INSERT INTO user_auth_providers (user_id, auth_provider_id) VALUES(@user_id, @auth_provider_id) ON CONFLICT DO NOTHING"
	UpdateUserAuthProviderSql = "UPDATE user_auth_providers SET updated_at = @time WHERE user_id = @user_id AND auth_provider_id = @auth_provider_id"

	UserAuthProvidersSql = `SELECT
		ap.id as id,
		ap.name as name,
		uap.updated_at as updated_at
		FROM user_auth_providers uap
		JOIN auth_providers ap ON uap.auth_provider_id = ap.id
		WHERE uap.user_id = @id::uuid
		`
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

func (pgdb *PostgresUserDB) NumUsers() (int, error) {

	var n int

	err := pgdb.db.QueryRow(pgdb.ctx, CountUsersSql).Scan(&n)

	if err != nil {
		return 0, err
	}

	return n, nil
}

func (pgdb *PostgresUserDB) Users(records int, offset int) ([]*auth.AuthUser, error) {
	log.Debug().Msgf("users %d %d %s", records, offset, UsersSql)

	tx, err := pgdb.db.BeginTx(pgdb.ctx, pgx.TxOptions{
		AccessMode: pgx.ReadOnly,
	})

	if err != nil {
		return nil, err
	}

	defer tx.Rollback(pgdb.ctx)

	rows, err := tx.Query(pgdb.ctx, UsersSql, pgx.NamedArgs{"limit": records, "offset": offset})

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
			Groups:  make([]*auth.RBACGroup, 0, 5),
			ApiKeys: make([]string, 0, 5),
		}

		err := rows.Scan(&authUser.Id,
			&authUser.Name,
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

		err = pgdb.addGroupsToUser(tx, &authUser)

		if err != nil {
			return nil, err
		}

		err = pgdb.addAuthProvidersToUser(tx, &authUser)

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
		return auth.NewAccountError("cannot delete admin account")
	}

	_, err = pgdb.db.Exec(pgdb.ctx, DeleteUserSql, pgx.NamedArgs{"id": id})

	if err != nil {
		return err
	}

	return nil
}

func (pgdb *PostgresUserDB) FindUserByEmail(email *mail.Address) (*auth.AuthUser, error) {
	log.Debug().Msgf("find email user %s %v", FindUserByEmailSql, email.Address)
	return pgdb.findUser(email.Address, FindUserByEmailSql, pgx.NamedArgs{"email": email.Address})
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

	return pgdb.findUser(username,
		FindUserByUsernameSql,
		pgx.NamedArgs{"username": username})
}

func (pgdb *PostgresUserDB) FindUserById(id string) (*auth.AuthUser, error) {

	return pgdb.findUser(id, FindUserByIdSql, pgx.NamedArgs{"id": id})
}

// func (pgdb *PostgresUserDB) FindUserByPublicId(publicId string) (*auth.AuthUser, error) {
// 	return pgdb.findUser(publicId, pgdb.db.QueryRow(pgdb.ctx, FindUserByPublicIdSql, publicId))
// }

// Helper function used by various FindUser methods. Converts a db row to an AuthUser
func (pgdb *PostgresUserDB) findUser(id string,
	sql string,
	sqlParams pgx.NamedArgs) (*auth.AuthUser, error) {

	tx, err := pgdb.db.BeginTx(pgdb.ctx,
		pgx.TxOptions{
			AccessMode: pgx.ReadOnly,
		})

	if err != nil {
		return nil, fmt.Errorf("failed to begin read-only transaction: %v", err)
	}

	defer tx.Rollback(pgdb.ctx)

	row := tx.QueryRow(pgdb.ctx, sql, sqlParams)

	var authUser auth.AuthUser
	//var updatedAt int64

	err = row.Scan(&authUser.Id,
		&authUser.Name,
		&authUser.Username,
		&authUser.Email,
		&authUser.IsLocked,
		&authUser.HashedPassword,
		&authUser.EmailVerifiedAt,
		&authUser.CreatedAt,
		&authUser.UpdatedAt)

	if err != nil {
		return nil, auth.NewUserNotFoundError(id)
	}

	//authUser.UpdatedAt = time.Duration(updatedAt)

	err = pgdb.addGroupsToUser(tx, &authUser)

	if err != nil {
		log.Error().Msgf("error adding roles to user %s %v", authUser.Id, err)
		return nil, err
	}

	err = pgdb.addAuthProvidersToUser(tx, &authUser)

	if err != nil {
		return nil, err
	}

	err = pgdb.addApiKeysToUser(tx, &authUser)

	if err != nil {
		return nil, err
	}

	err = pgdb.addPublicKeysToUser(tx, &authUser)

	if err != nil {
		return nil, err
	}

	return &authUser, nil
}

func (pgdb *PostgresUserDB) FindUserByApiKey(key string) (*auth.AuthUser, error) {

	if !sys.IsValidUUID(key) {
		return nil, auth.NewAccountError("api key is not in valid format")
	}

	var id string
	var userId string
	//var createdAt int64

	err := pgdb.db.QueryRow(pgdb.ctx, FindUserByApiKeySql, pgx.NamedArgs{"api_key": key}).Scan(&id,
		&userId, &key)

	if err != nil {
		return nil, err
	}

	return pgdb.FindUserById(userId)
}

func (pgdb *PostgresUserDB) addGroupsToUser(tx pgx.Tx, authUser *auth.AuthUser) error {

	groups, err := pgdb.userGroups(tx, authUser)

	//log.Debug().Msgf("add groups to user %s: %v", authUser.Username, groups)

	if err != nil {
		return err //fmt.Errorf("there was an error with the database query")
	}

	authUser.Groups = append(authUser.Groups, groups...)

	return nil
}

func (pgdb *PostgresUserDB) addAuthProvidersToUser(tx pgx.Tx, user *auth.AuthUser) error {

	rows, err := tx.Query(pgdb.ctx, UserAuthProvidersSql, pgx.NamedArgs{"id": user.Id})

	if err != nil {
		return auth.NewAccountError("user auth providers not found: " + err.Error())
	}

	defer rows.Close()

	user.AuthProviders = make([]*auth.AuthProvider, 0, 10)

	for rows.Next() {
		var provider auth.AuthProvider

		err := rows.Scan(
			&provider.Id,
			&provider.Name,
			&provider.UpdatedAt)

		if err != nil {
			log.Error().Msgf("error scanning user groups %v", err)
			return fmt.Errorf("user roles not found: %v", err)
		}

		user.AuthProviders = append(user.AuthProviders, &provider)
	}

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

func (pgdb *PostgresUserDB) addApiKeysToUser(tx pgx.Tx, user *auth.AuthUser) error {

	rows, err := tx.Query(pgdb.ctx, UserApiKeysSql, pgx.NamedArgs{"id": user.Id})

	if err != nil {
		return errors.New("user roles not found")
	}

	defer rows.Close()

	user.ApiKeys = make([]string, 0, 10)

	var id string
	var key string

	for rows.Next() {

		err := rows.Scan(&id, &key)

		if err != nil {
			return err
		}
		user.ApiKeys = append(user.ApiKeys, key)
	}

	return nil
}

func (pgdb *PostgresUserDB) addPublicKeysToUser(tx pgx.Tx, user *auth.AuthUser) error {

	rows, err := tx.Query(pgdb.ctx, UserPublicKeysSql, pgx.NamedArgs{"id": user.Id})

	if err != nil {
		return fmt.Errorf("user public keys not found")
	}

	defer rows.Close()

	user.PublicKeys = make([]*auth.PublicKey, 0, 10)

	for rows.Next() {
		var key auth.PublicKey
		err := rows.Scan(&key.Id, &key.Name, &key.Key)

		if err != nil {
			return err
		}

		user.PublicKeys = append(user.PublicKeys, &key)
	}

	return nil
}

func (pgdb *PostgresUserDB) userGroups(tx pgx.Tx, user *auth.AuthUser) ([]*auth.RBACGroup, error) {

	log.Debug().Msgf("getting user groups for %s", user.Id)

	rows, err := tx.Query(pgdb.ctx, UserGroupsSql, pgx.NamedArgs{"id": user.Id})
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

		log.Debug().Msgf("current permission: %v %v", currentRole, currentPermission)

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
		return nil, auth.NewAccountError(fmt.Sprintf("%s role not found", name))
	}

	return &role, nil
}

// FindGroupByName finds group by public id or name
func (pgdb *PostgresUserDB) FindGroupById(id string) (*auth.RBACGroup, error) {

	var group auth.RBACGroup

	err := pgdb.db.QueryRow(pgdb.ctx, FindGroupByIdSql, pgx.NamedArgs{"id": id}).Scan(&group.Id,
		&group.Name,
		&group.Description)

	//log.Debug().Msgf("find group %v err %v", group, err)

	if err != nil {
		return nil, auth.NewAccountError(fmt.Sprintf("%s group not found: %v", id, err))
	}

	return &group, nil
}

func (pgdb *PostgresUserDB) FindGroupByName(name string) (*auth.RBACGroup, error) {

	var group auth.RBACGroup

	err := pgdb.db.QueryRow(pgdb.ctx, FindGroupByNameSql, pgx.NamedArgs{"name": name}).Scan(&group.Id,
		&group.Name,
		&group.Description)

	//log.Debug().Msgf("find group %v err %v", group, err)

	if err != nil {
		return nil, auth.NewAccountError(fmt.Sprintf("%s group not found: %v", name, err))
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

// set that the email is verified by updating the verification timestamp
// to something other than epoch date
func (pgdb *PostgresUserDB) SetEmailIsVerified(user *auth.AuthUser) (*time.Time, error) {

	// use in utc
	now := time.Now().UTC()

	_, err := pgdb.db.Exec(pgdb.ctx, SetEmailVerifiedSql, pgx.NamedArgs{"id": user.Id, "time": now})

	if err != nil {
		return nil, auth.NewAccountError("could not verify email address")
	}

	user.EmailVerifiedAt = &now

	// _, err = pgdb.setOtpStmt.Exec(pgdb.ctx,"", userId)

	// if err != nil {
	// 	return false
	// }

	return &now, nil
}

func (pgdb *PostgresUserDB) SetUsername(user *auth.AuthUser, username string, adminMode bool) (string, error) {
	if !adminMode && user.IsLocked {
		return "", auth.NewAccountError("account is locked and cannot be edited")
	}

	_, err := pgdb.db.Exec(pgdb.ctx, SetUsernameSql, pgx.NamedArgs{"username": username, "id": user.Id})

	if err != nil {
		return "", auth.NewAccountError("could not update username")
	}

	user.Username = username

	return username, err
}

func (pgdb *PostgresUserDB) SetPassword(user *auth.AuthUser, password string, adminMode bool) (string, error) {
	if !adminMode && user.IsLocked {
		return "", auth.NewAccountError("account is locked and cannot be edited")
	}

	var err error

	err = userdb.CheckPassword(password)

	if err != nil {
		return "", err
	}

	hash := ""

	if password != "" {
		hash = auth.HashPassword(password)
	}

	_, err = pgdb.db.Exec(pgdb.ctx, SetPasswordSql, pgx.NamedArgs{"password": hash, "id": user.Id})

	if err != nil {
		return "", auth.NewAccountError("could not update password")
	}

	user.HashedPassword = hash

	return hash, err
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
	name string,
	adminMode bool) error {

	if !adminMode {
		if user.IsLocked {
			return auth.NewAccountError("account is locked and cannot be edited")
		}

		err := userdb.CheckUsername(username)

		if err != nil {
			return err
		}

		err = userdb.CheckName(name)

		if err != nil {
			return err
		}
	}

	_, err := pgdb.db.Exec(pgdb.ctx, SetInfoSql, pgx.NamedArgs{"username": username, "name": name, "id": user.Id})

	if err != nil {
		return auth.NewAccountError("could not update user info")
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
		return auth.NewAccountError("account is locked and cannot be edited")
	}

	_, err := pgdb.db.Exec(pgdb.ctx, SetEmailSql, pgx.NamedArgs{"email": address.Address, "id": user.Id})

	if err != nil {
		return auth.NewAccountError("could not update email address")
	}

	return nil
}

func (pgdb *PostgresUserDB) SetUserGroups(user *auth.AuthUser, groups []string, adminMode bool) error {
	if !adminMode && user.IsLocked {
		return auth.NewAccountError("account is locked and cannot be edited")
	}

	// remove existing roles,
	_, err := pgdb.db.Exec(pgdb.ctx, DeleteUserGroupsSql, pgx.NamedArgs{"id": user.Id})

	if err != nil {
		return err
	}

	for _, group := range groups {
		g, err := pgdb.FindGroupByName(group)

		if err != nil {
			return err
		}

		err = pgdb.AddUserToGroup(user, g, adminMode)

		if err != nil {
			return auth.NewAccountError(fmt.Sprintf("could not add user to group %s: %v", group, err))
		}
	}

	return nil
}

func (pgdb *PostgresUserDB) AddUserToGroup(user *auth.AuthUser, group *auth.RBACGroup, adminMode bool) error {
	if !adminMode && user.IsLocked {
		return auth.NewAccountError("account is locked and cannot be edited")
	}

	_, err := pgdb.db.Exec(pgdb.ctx, InsertUserGroupSql, pgx.NamedArgs{"user_id": user.Id, "group_id": group.Id})

	if err != nil {
		return auth.NewAccountError(fmt.Sprintf("could not add user to group: %v", err))
	}

	return nil
}

func (pgdb *PostgresUserDB) CreateApiKeyForUser(user *auth.AuthUser, adminMode bool) error {
	if !adminMode && user.IsLocked {
		return auth.NewAccountError("account is locked and cannot be edited")
	}

	uuid, err := sys.Uuidv7()

	if err != nil {
		return err
	}

	_, err = pgdb.db.Exec(pgdb.ctx, InsertApiKeySql, pgx.NamedArgs{"user_id": user.Id, "api_key": uuid})

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
	return pgdb.CreateOrUpdateUser(email, userName, user.Password, user.Name, false, "edb")
}

// Gets the user info from the database and auto creates user if
// user does not exist since we Auth0 has authenticated them
func (pgdb *PostgresUserDB) CreateUserFromOAuth2(email *mail.Address,
	name string,
	authProvider string) (*auth.AuthUser, error) {
	//authUser, err := pgdb.FindUserByEmail(email)

	//if err == nil {
	//	return authUser, nil
	//}

	// user does not exist so create
	return pgdb.CreateOrUpdateUser(email, email.Address, "", name, true, authProvider)

}

func (pgdb *PostgresUserDB) FindAuthProviderByName(name string) (*auth.AuthProvider, error) {
	// run insert every time with on conflict
	_, err := pgdb.db.Exec(pgdb.ctx, InsertAuthProviderSql, pgx.NamedArgs{"name": name})

	if err != nil {
		return nil, err
	}

	row := pgdb.db.QueryRow(pgdb.ctx, FindAuthProviderByNameSql, pgx.NamedArgs{"name": name})

	var authProvider auth.AuthProvider

	err = row.Scan(&authProvider.Id, &authProvider.Name)

	if err != nil {
		return nil, err
	}

	return &authProvider, nil
}

func (pgdb *PostgresUserDB) AddUserAuthProvider(user *auth.AuthUser, authProvider *auth.AuthProvider) error {
	now := time.Now().UTC()

	_, err := pgdb.db.Exec(pgdb.ctx, InsertUserAuthProviderSql, pgx.NamedArgs{"user_id": user.Id, "auth_provider_id": authProvider.Id})

	if err != nil {
		return err
	}

	_, err = pgdb.db.Exec(pgdb.ctx, UpdateUserAuthProviderSql, pgx.NamedArgs{"user_id": user.Id, "auth_provider_id": authProvider.Id, "time": now})

	return err
}

// Will create a user if they don't exist or otherwise update the
// existing user with info provided
func (pgdb *PostgresUserDB) CreateOrUpdateUser(email *mail.Address,
	userName string,
	password string,
	name string,
	emailIsVerified bool,
	authProvider string) (*auth.AuthUser, error) {
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
		return pgdb.updateUser(authUser,
			email,
			userName,
			password,
			name,
			emailIsVerified,
			authProvider)
	}

	return pgdb.CreateUser(email,
		userName,
		password,
		name,
		emailIsVerified,
		authProvider)
}

func (pgdb *PostgresUserDB) CreateUser(email *mail.Address,
	userName string,
	password string,
	name string,
	emailIsVerified bool,
	authProvider string) (*auth.AuthUser, error) {
	log.Debug().Msgf("create user start %s %s", email.Address, userName)

	err := userdb.CheckPassword(password)

	if err != nil {
		return nil, err
	}

	hash := auth.HashPassword(password)

	// default to unverified i.e. if time is epoch (1970) assume
	// unverified
	var emailVerifiedAt *time.Time = nil //userdb.EmailNotVerifiedDate

	if emailIsVerified {
		now := time.Now().UTC()
		emailVerifiedAt = &now
	}

	log.Debug().Msgf("%s %s", email.Address, emailVerifiedAt)

	_, err = pgdb.db.Exec(pgdb.ctx,
		InsertUserSql,
		pgx.NamedArgs{
			"username":          userName,
			"email":             email.Address,
			"password":          hash,
			"name":              name,
			"email_verified_at": emailVerifiedAt,
		},
	)

	if err != nil {
		log.Debug().Msgf("error making person %s %v", email.Address, err)
		return nil, err
	}

	// Call function again to get the user details
	authUser, err := pgdb.FindUserByEmail(email)

	if err != nil {
		log.Debug().Msgf("find by error user %v", err)
		return nil, err
	}

	log.Debug().Msgf("created user %v", authUser)

	group, err := pgdb.FindGroupByName(auth.GroupLogin)

	if err != nil {
		return nil, err
	}

	// Give user standard role and ability to login
	err = pgdb.AddUserToGroup(authUser, group, true)

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

	log.Debug().Msgf("created user end %v", authUser)

	// return the updated version
	return pgdb.FindUserById(authUser.Id)
}

func (pgdb *PostgresUserDB) updateUser(authUser *auth.AuthUser,
	email *mail.Address,
	username string,
	password string,
	name string,
	emailIsVerified bool,
	authProvider string) (*auth.AuthUser, error) {
	err := userdb.CheckPassword(password)

	if err != nil {
		return nil, err
	}

	log.Debug().Msgf("create user found %v %s", authUser, email)

	// user already exists so check if verified

	//if authUser.EmailVerifiedAt > userdb.EmailNotVerifiedDate {
	//	return nil, auth.NewAccountError("user already registered: please sign up with a different email address")
	//}

	if emailIsVerified {
		_, err := pgdb.SetEmailIsVerified(authUser)

		if err != nil {
			return nil, err
		}

	}

	// if user is not verified, update the password since we assume
	// rightful owner of email address will keep trying until verified
	// this is to stop people blocking creation of accounts by just
	// signing up with email addresses they have no intention of
	// verifying. Since createUser is called by oauth2 signins and
	// may be updating an existing account, we do not update password
	// if user account is locked.
	if !authUser.IsLocked {
		//_, err := pgdb.SetUsername(authUser, username, false)

		err := pgdb.SetUserInfo(authUser, username, name, false)

		if err != nil {
			return nil, err
		}

		_, err = pgdb.SetPassword(authUser, password, false)

		if err != nil {
			return nil, err
		}
	}

	// add info about signin
	ap, err := pgdb.FindAuthProviderByName(authProvider)
	if err != nil {
		return nil, err
	}

	err = pgdb.AddUserAuthProvider(authUser, ap)

	if err != nil {
		return nil, err
	}

	// ensure user is the updated version
	return authUser, nil //pgdb.FindUserById(authUser.Id)

}
