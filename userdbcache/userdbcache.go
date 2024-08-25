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

func CreateStandardUser(user *auth.SignupReq) (*auth.AuthUser, error) {
	return instance.CreateStandardUser(user)
}

func FindUserById(id string) (*auth.AuthUser, error) {
	return instance.FindUserById(id)
}

func FindUserByEmail(email *mail.Address) (*auth.AuthUser, error) {
	return instance.FindUserByEmail(email)
}

func FindUserByUsername(username string) (*auth.AuthUser, error) {
	return instance.FindUserByUsername(username)
}

func FindUserByUuid(uuid string) (*auth.AuthUser, error) {
	return instance.FindUserByUuid(uuid)
}

func UserRoles(user *auth.AuthUser) (*[]auth.Role, error) {
	return instance.UserRoles(user)
}

func RoleList(user *auth.AuthUser) (*[]string, error) {

	roles, err := instance.UserRoles(user)

	if err != nil {
		return nil, err
	}

	ret := make([]string, len(*roles))

	for ri, role := range *roles {
		ret[ri] = role.Name
	}

	return &ret, nil

	//ret := strings.Join(tokens, ",")

	//return ret, nil

}

func UserPermissions(user *auth.AuthUser) (*[]auth.Permission, error) {
	return instance.UserPermissions(user)
}

func Users(offset int, records int) ([]*auth.AuthUser, error) {
	return instance.Users(offset, records)
}

func PermissionList(user *auth.AuthUser) (*[]string, error) {

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

func SetPassword(uuid string, password string) error {
	return instance.SetPassword(uuid, password)
}

func SetUsername(uuid string, username string) error {
	return instance.SetUsername(uuid, username)
}

func SetName(uuid string, firstName string, lastName string) error {
	return instance.SetName(uuid, firstName, lastName)
}

func SetUserInfo(uuid string, username string, firstName string, lastName string) error {
	return instance.SetUserInfo(uuid, username, firstName, lastName)
}

func SetEmail(uuid string, email string) error {
	return instance.SetEmail(uuid, email)
}

func SetEmailAddress(uuid string, address *mail.Address) error {
	return instance.SetEmailAddress(uuid, address)
}
