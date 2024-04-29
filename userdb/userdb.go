package userdb

import (
	"net/mail"

	"github.com/antonybholmes/go-auth"
)

// pretend its a global const
var userdb *auth.UserDb

func InitDB(file string) error {
	var err error

	userdb, err = auth.NewUserDB(file)

	return err

}

func CreateUser(user *auth.SignupReq) (*auth.AuthUser, error) {
	return userdb.CreateUser(user)
}

func FindUserById(id string) (*auth.AuthUser, error) {
	return userdb.FindUserById(id)
}

func FindUserByEmail(email *mail.Address) (*auth.AuthUser, error) {
	return userdb.FindUserByEmail(email)
}

func FindUserByUsername(username string) (*auth.AuthUser, error) {
	return userdb.FindUserByUsername(username)
}

func FindUserByUuid(uuid string) (*auth.AuthUser, error) {
	return userdb.FindUserByUuid(uuid)
}

func SetIsVerified(user string) error {
	return userdb.SetIsVerified(user)
}

func SetPassword(uuid string, password string) error {
	return userdb.SetPassword(uuid, password)
}

func SetUsername(uuid string, username string) error {
	return userdb.SetUsername(uuid, username)
}

func SetName(uuid string, firstName string, lastName string) error {
	return userdb.SetName(uuid, firstName, lastName)
}

func SetUserInfo(uuid string, username string, firstName string, lastName string) error {
	return userdb.SetUserInfo(uuid, username, firstName, lastName)
}

func SetEmail(uuid string, email string) error {
	return userdb.SetEmail(uuid, email)
}

func SetEmailAddress(uuid string, address *mail.Address) error {
	return userdb.SetEmailAddress(uuid, address)
}
