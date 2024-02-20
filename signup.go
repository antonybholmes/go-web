package auth

import (
	"fmt"

	"github.com/antonybholmes/go-mailer"
	"golang.org/x/crypto/bcrypt"
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
	return fmt.Sprintf("%s:%s:%s", user.Name, user.Email, user.Password)
}

// func NewSignupUser(name string, email string, password string) *SignupUser {
// 	return &SignupUser{User: User{Name: name, Email: email}, Password: password}
// }

// func SignupUserFromReq(req *SignupReq) *SignupUser {
// 	return NewSignupUser(req.Name, req.Email, req.Password)
// }

// Returns the hash of the password suitable for storing in a db.
// We allow empty passwords for passwordless login
func (user *SignupReq) Hash() (string, error) {
	if user.Password == "" {
		return "", nil
	}

	bytes, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)

	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

func (user *SignupReq) Mailbox() *mailer.Mailbox {
	return mailer.NewMailbox(user.Name, user.Email)
}
