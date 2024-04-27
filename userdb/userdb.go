package userdb

import (
	"net/mail"

	"github.com/antonybholmes/go-auth"
)

// pretend its a global const
var users *auth.UserDb = new(auth.UserDb)

func InitDB(file string) error {
	var err error

	users, err = auth.NewUserDB(file)

	return err

}

func CreateUser(user *auth.SignupReq) (*auth.AuthUser, error) {
	return users.CreateUser(user)
}

func FindUserByEmail(email *mail.Address) (*auth.AuthUser, error) {
	return users.FindUserByEmail(email)
}

func FindUserByUsername(username string) (*auth.AuthUser, error) {
	return users.FindUserByUsername(username)
}

func FindUserByUuid(uuid string) (*auth.AuthUser, error) {
	return users.FindUserByUuid(uuid)
}

func SetIsVerified(user string) error {
	return users.SetIsVerified(user)
}

func SetPassword(uuid string, password string) error {
	return users.SetPassword(uuid, password)
}

func SetUsername(uuid string, username string) error {
	return users.SetUsername(uuid, username)
}

func SetName(uuid string, firstName string, lastName string) error {
	return users.SetName(uuid, firstName, lastName)
}

func SetEmail(uuid string, email string) error {
	return users.SetEmail(uuid, email)
}

func SetEmailAddress(uuid string, address *mail.Address) error {
	return users.SetEmailAddress(uuid, address)
}
