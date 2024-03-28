package auth

import (
	"fmt"
	"net/mail"
	"strings"
)

// type SignupUser struct {
// 	User
// 	Password string `json:"password"`
// }

type SignupReq struct {
	User
	Password string `json:"password"`
	UrlCallbackReq
}

func (user *SignupReq) String() string {
	return fmt.Sprintf("%s:%s:%s", user.FirstName, user.Email, user.Password)
}

// func NewSignupUser(name string, email string, password string) *SignupUser {
// 	return &SignupUser{User: User{Name: name, Email: email}, Password: password}
// }

// func SignupUserFromReq(req *SignupReq) *SignupUser {
// 	return NewSignupUser(req.Name, req.Email, req.Password)
// }

// Returns the hash of the password suitable for storing in a db.
// We allow empty passwords for passwordless login
func (user *SignupReq) HashedPassword() string {
	return HashPassword(user.Password)
}

func (user *SignupReq) Address() (*mail.Address, error) {
	email, err := mail.ParseAddress(user.Email)

	if err != nil {
		return nil, err
	}

	email.Name = strings.TrimSpace(fmt.Sprintf("%s %s", user.FirstName, user.LastName))

	return email, nil
}
