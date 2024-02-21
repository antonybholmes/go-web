package userdb

import (
	"github.com/antonybholmes/go-auth"
)

// pretend its a global const
var users *auth.UserDb = new(auth.UserDb)

func Init(file string) error {
	return users.Init(file)
}

func CreateUser(user *auth.SignupReq) (*auth.AuthUser, error) {
	return users.CreateUser(user)
}

func FindUserByEmail(email string) (*auth.AuthUser, error) {
	return users.FindUserByEmail(email)
}

func FindUserById(user string) (*auth.AuthUser, error) {
	return users.FindUserById(user)
}

func SetIsVerified(user string) error {
	return users.SetIsVerified(user)
}

func SetPassword(user string, password string) error {
	return users.SetPassword(user, password)
}
