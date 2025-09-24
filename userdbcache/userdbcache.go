package userdbcache

import (
	"net/mail"
	"sync"

	"github.com/antonybholmes/go-sys"
	"github.com/antonybholmes/go-web/auth"
)

// pretend its a global const
var instance *auth.UserDb
var once sync.Once

func InitCache() {

	//instance, err = auth.NewUserDB(file)

	once.Do(func() {
		instance = auth.NewUserDB()
	})

}

func Instance() *auth.UserDb {
	return instance
}

// func NewConn() (*sql.DB, error) {
// 	return instance.NewConn()
// }

// func AutoConn(db *sql.DB) (*sql.DB, error) {
// 	return instance.AutoConn(db)
// }

func NumUsers() (uint, error) {
	return instance.NumUsers()
}

func Roles() ([]*auth.Role, error) {
	return instance.Roles()
}

func Users(records uint, offset uint) ([]*auth.AuthUser, error) {
	return instance.Users(records, offset)
}

func CreateUserFromSignup(user *auth.UserBodyReq) (*auth.AuthUser, error) {
	return instance.CreateUserFromSignup(user)
}

func CreateUserFromOAuth2(name string, email *mail.Address) (*auth.AuthUser, error) {
	return instance.CreateUserFromOAuth2(name, email)
}

func FindUserById(id uint) (*auth.AuthUser, error) {
	return instance.FindUserById(id)
}

func FindUserByPublicId(uuid string) (*auth.AuthUser, error) {
	return instance.FindUserByPublicId(uuid)
}

func FindUserByUsername(username string) (*auth.AuthUser, error) {
	return instance.FindUserByUsername(username)
}

func FindUserByApiKey(key string) (*auth.AuthUser, error) {
	return instance.FindUserByApiKey(key)
}

func FindUserByEmail(email *mail.Address) (*auth.AuthUser, error) {
	return instance.FindUserByEmail(email)
}

func UserRoles(user *auth.AuthUser) ([]*auth.Role, error) {
	return instance.UserRoles(user)
}

// returns a string list of a user's roles
func UserRoleList(user *auth.AuthUser) ([]string, error) {

	roles, err := instance.UserRoles(user)

	if err != nil {
		return nil, err
	}

	// map roles to strings
	ret := make([]string, len(roles))

	for ri, role := range roles {
		ret[ri] = role.Name
	}

	return ret, nil
}

func UserRoleSet(user *auth.AuthUser) (*sys.StringSet, error) {

	roles, err := instance.UserRoleList(user)

	if err != nil {
		return nil, err
	}

	roleSet := sys.NewStringSet()

	roleSet.UpdateFromList(roles)

	return roleSet, nil
}

func UserPermissions(user *auth.AuthUser) ([]*auth.Permission, error) {
	return instance.UserPermissions(user)
}

func PermissionList(user *auth.AuthUser) ([]string, error) {
	return instance.PermissionList(user)
}

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

func SetUserRoles(user *auth.AuthUser, roles []string, adminMode bool) error {
	return instance.SetUserRoles(user, roles, adminMode)
}

func DeleteUser(publicId string) error {
	return instance.DeleteUser(publicId)
}
