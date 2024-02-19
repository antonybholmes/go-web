package auth

import (
	"fmt"

	"github.com/antonybholmes/go-mailer"
	"golang.org/x/crypto/bcrypt"
)

type SignupReq struct {
	User
	Password string `json:"password"`
	UrlCallbackReq
}

type SignupUser struct {
	User
	Password []byte `json:"password"`
}

func (user *SignupUser) String() string {
	return fmt.Sprintf("%s:%s:%s", user.Name, user.Email, user.Password)
}

func NewSignupUser(name string, email string, password string) *SignupUser {
	return &SignupUser{User: User{Name: name, Email: email}, Password: []byte(password)}
}

func SignupUserFromReq(req *SignupReq) *SignupUser {
	return NewSignupUser(req.Name, req.Email, req.Password)
}

func (user *SignupUser) HashPassword() ([]byte, error) {
	bytes, err := bcrypt.GenerateFromPassword(user.Password, bcrypt.DefaultCost)

	if err != nil {
		return nil, err
	}

	return bytes, nil
}

func (user *SignupUser) Mailbox() *mailer.Mailbox {
	return mailer.NewMailbox(user.Name, user.Email)
}
