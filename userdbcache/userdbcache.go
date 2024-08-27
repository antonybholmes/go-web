package userdbcache

import (
	"net/mail"
	"sync"

	"github.com/antonybholmes/go-auth"
)

// pretend its a global const
var instance *auth.UserDb
var once sync.Once

func InitCache(file string) {

	//instance, err = auth.NewUserDB(file)

	once.Do(func() {
		instance = auth.NewUserDB(file)
	})

}

func NumUsers() (uint, error) {
	return instance.NumUsers()
}

func Roles() ([]*auth.Role, error) {
	return instance.Roles()
}

func Users(offset int, records int) ([]*auth.AuthUser, error) {
	return instance.Users(offset, records)
}

func CreateUserFromSignup(user *auth.SignupReq) (*auth.AuthUser, error) {
	return instance.CreateUserFromSignup(user)
}

func FindUserById(id int) (*auth.AuthUser, error) {
	return instance.FindUserById(id)
}

func FindUserByPublicId(publicId string) (*auth.AuthUser, error) {
	return instance.FindUserByPublicId(publicId)
}

func FindUserByUsername(username string) (*auth.AuthUser, error) {
	return instance.FindUserByUsername(username)
}

func FindUserByEmail(email *mail.Address) (*auth.AuthUser, error) {
	return instance.FindUserByEmail(email, nil)
}

func UserRoles(user *auth.AuthUser) ([]*auth.Role, error) {
	return instance.UserRoles(user)
}

func RoleList(user *auth.AuthUser) ([]string, error) {

	roles, err := instance.UserRoles(user)

	if err != nil {
		return nil, err
	}

	ret := make([]string, len(roles))

	for ri, role := range roles {
		ret[ri] = role.Name
	}

	return ret, nil

	//ret := strings.Join(tokens, ",")

	//return ret, nil

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

func SetUsername(publicId string, username string) error {
	return instance.SetUsername(publicId, username)
}

func SetName(publicId string, firstName string, lastName string) error {
	return instance.SetName(publicId, firstName, lastName)
}

func SetUserInfo(publicId string, username string, firstName string, lastName string) error {
	return instance.SetUserInfo(publicId, username, firstName, lastName)
}

func SetEmail(publicId string, email string) error {
	return instance.SetEmail(publicId, email)
}

func SetEmailAddress(publicId string, address *mail.Address) error {
	return instance.SetEmailAddress(publicId, address)
}
