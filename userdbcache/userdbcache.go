package userdbcache

import (
	"net/mail"
	"sync"

	"github.com/antonybholmes/go-auth"
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

func Users(records uint, offset uint) ([]*auth.AuthUserAdminView, error) {
	return instance.Users(records, offset)
}

func CreateUserFromSignup(user *auth.LoginBodyReq) (*auth.AuthUser, error) {
	return instance.CreateUserFromSignup(user)
}

func CreateUserFromAuth0(name string, email *mail.Address) (*auth.AuthUser, error) {
	return instance.CreateUserFromAuth0(name, email)
}

func FindUserById(id uint) (*auth.AuthUser, error) {
	return instance.FindUserById(id)
}

func FindUserByPublicId(publicId string) (*auth.AuthUser, error) {
	return instance.FindUserByPublicId(publicId)
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
	return instance.UserRoles(user.Id)
}

// returns a string list of a user's roles
func UserRoleList(user *auth.AuthUser) ([]string, error) {

	roles, err := instance.UserRoles(user.Id)

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

func SetPassword(publicId string, password string) error {
	return instance.SetPassword(publicId, password)
}

// func SetUsername(publicId string, username string) error {
// 	return instance.SetUsername(publicId, username)
// }

// func SetName(publicId string, firstName string, lastName string) error {
// 	return instance.SetName(publicId, firstName, lastName)
// }

func SetUserInfo(publicId string, username string, firstName string, lastName string) error {
	return instance.SetUserInfo(publicId, username, firstName, lastName)
}

// func SetEmail(publicId string, email string) error {
// 	return instance.SetEmail(publicId, email)
// }

func SetEmailAddress(publicId string, address *mail.Address) error {
	return instance.SetEmailAddress(publicId, address)
}

func SetUserRoles(user *auth.AuthUser, roles []string) error {
	return instance.SetUserRoles(user, roles)
}

func DeleteUser(publicId string) error {
	return instance.DeleteUser(publicId)
}
