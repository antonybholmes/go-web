package cache

import (
	"net/mail"
	"sync"

	"github.com/antonybholmes/go-web/auth"
	"github.com/antonybholmes/go-web/auth/userdb"
	"github.com/antonybholmes/go-web/auth/userdb/postgres"
)

// pretend its a global const
var instance userdb.UserDB
var once sync.Once

func InitCache() {

	//instance, err = auth.NewUserDB(file)

	// once.Do(func() {
	// 	instance = userdb.NewUserDBMySQL()
	// })

	once.Do(func() {
		instance = postgres.NewPostgresUserDB()
	})

}

func Instance() userdb.UserDB {
	return instance
}

// func NewConn() (*sql.DB, error) {
// 	return instance.NewConn()
// }

// func AutoConn(db *sql.DB) (*sql.DB, error) {
// 	return instance.AutoConn(db)
// }

func NumUsers() (int, error) {
	return instance.NumUsers()
}

func Roles() ([]*auth.RBACRole, error) {
	return instance.Roles()
}

func Groups() ([]*auth.RBACGroup, error) {
	return instance.Groups()
}

func Users(records int, offset int) ([]*auth.AuthUser, error) {
	return instance.Users(records, offset)
}

func CreateUserFromSignup(user *auth.UserBodyReq) (*auth.AuthUser, error) {
	return instance.CreateUserFromSignup(user)
}

func CreateUserFromOAuth2(name string, email *mail.Address) (*auth.AuthUser, error) {
	return instance.CreateUserFromOAuth2(name, email)
}

func FindUserById(id string) (*auth.AuthUser, error) {
	return instance.FindUserById(id)
}

// func FindUserByPublicId(uuid string) (*auth.AuthUser, error) {
// 	return instance.FindUserByPublicId(uuid)
// }

func FindUserByUsername(username string) (*auth.AuthUser, error) {
	return instance.FindUserByUsername(username)
}

func FindUserByApiKey(key string) (*auth.AuthUser, error) {
	return instance.FindUserByApiKey(key)
}

func FindUserByEmail(email *mail.Address) (*auth.AuthUser, error) {
	return instance.FindUserByEmail(email)
}

func UserGroups(user *auth.AuthUser) ([]*auth.RBACGroup, error) {
	return instance.UserGroups(user)
}

// // returns a string list of a user's roles
// func UserGroupList(user *auth.AuthUser) ([]string, error) {

// 	roles, err := instance.UserGroups(user)

// 	if err != nil {
// 		return nil, err
// 	}

// 	// map roles to strings
// 	ret := make([]string, len(roles))

// 	for ri, role := range roles {
// 		ret[ri] = role.Name
// 	}

// 	return ret, nil
// }

// func UserRoleSet(user *auth.AuthUser) (*sys.StringSet, error) {

// 	roles, err := instance.UserRoleList(user)

// 	if err != nil {
// 		return nil, err
// 	}

// 	roleSet := sys.NewStringSet()

// 	roleSet.ListUpdate(roles)

// 	return roleSet, nil
// }

// func UserPermissions(user *auth.AuthUser) ([]*auth.Permission, error) {
// 	return instance.Permissions(user)
// }

// func PermissionList(user *auth.AuthUser) ([]string, error) {
// 	return instance.PermissionList(user)
// }

// func PublicUserRolePermissions(user *auth.AuthUser) (*[]auth.PublicRole, error) {
// 	return instance.PublicUserRolePermissions(user)
// }

// func PublicUserRolePermissionsList(user *auth.AuthUser) (*auth.RoleMap, error) {

// 	roles, err := instance.UserRoles(user)

// 	if err != nil {
// 		return nil, err
// 	}

// 	ret := make(auth.RoleMap)

// 	for _, role := range *roles {
// 		//for _, permission := range role.Permissions {
// 		//	tokens = append(tokens, fmt.Sprintf("%s::%s", role.Name, permission))
// 		//}

// 		_, ok := ret[role.Name]

// 		if !ok {
// 			ret[role.Name] = make([]string, 0, 10)
// 		}

// 		ret[role.Name] = append(ret[role.Name], role.Permissions...)
// 	}

// 	return &ret, nil

// }

func SetIsVerified(user string) error {
	return instance.SetIsVerified(user)
}

func SetPassword(user *auth.AuthUser, password string) error {
	return instance.SetPassword(user, password)
}

// func SetUsername(publicId string, username string) error {
// 	return instance.SetUsername(publicId, username)
// }

// func SetName(publicId string, firstName string, lastName string) error {
// 	return instance.SetName(publicId, firstName, lastName)
// }

func SetUserInfo(user *auth.AuthUser, username string, firstName string, lastName string, adminMode bool) error {
	return instance.SetUserInfo(user, username, firstName, lastName, adminMode)
}

// func SetEmail(publicId string, email string) error {
// 	return instance.SetEmail(publicId, email)
// }

func SetEmailAddress(user *auth.AuthUser, address *mail.Address, adminMode bool) error {
	return instance.SetEmailAddress(user, address, adminMode)
}

func SetUserGroups(user *auth.AuthUser, groups []string, adminMode bool) error {
	return instance.SetUserGroups(user, groups, adminMode)
}

func DeleteUser(publicId string) error {
	return instance.DeleteUser(publicId)
}
