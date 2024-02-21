package auth

import (
	"strings"

	"github.com/antonybholmes/go-mailer"
	"github.com/gofrs/uuid/v5"
	"github.com/xyproto/randomstring"
	"golang.org/x/crypto/bcrypt"
)

type UrlReq struct {
	Url string `json:"url"`
}

type UrlCallbackReq struct {
	// the url that should form the email link in any emails that are sent
	CallbackUrl string `json:"callbackUrl"`
	// The url the callback url should redirect to once it completes
	Url string `json:"url"`
}

type User struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type PublicUser struct {
	UserId string `json:"user_id"`
	User
}

type AuthUser struct {
	PublicUser
	Id             int    `json:"int"`
	HashedPassword []byte `json:"hashed_password"`
	IsVerified     bool   `json:"isVerified"`
	CanAuth        bool   `json:"canAuth"`
}

func (user *AuthUser) Mailbox() *mailer.Mailbox {
	return mailer.NewMailbox(user.Name, user.Email)
}

func init() {
	randomstring.Seed()
}

func NewAuthUser(id int, userId string, name string, email string, hashedPassword string, isVerified bool, canAuth bool) *AuthUser {
	return &AuthUser{PublicUser: PublicUser{UserId: userId, User: User{Name: name, Email: email}},
		Id:             id,
		HashedPassword: []byte(hashedPassword),
		IsVerified:     isVerified,
		CanAuth:        canAuth}
}

func (user *AuthUser) CheckPasswords(plainPwd string) bool {
	// Since we'll be getting the hashed password from the DB it
	// will be a string so we'll need to convert it to a byte slice

	//log.Printf("comp %s %s\n", string(user.HashedPassword), string(plainPwd))

	err := bcrypt.CompareHashAndPassword(user.HashedPassword, []byte(plainPwd))

	return err == nil
}

func (user *AuthUser) ToPublicUser() *PublicUser {
	return &PublicUser{UserId: user.UserId,
		User: User{Name: user.Name, Email: user.Email}}
}

// Generate a one time code
func RandCode() string {
	return randomstring.CookieFriendlyString(32)
}

func Uuid() (string, error) {
	u1, err := uuid.NewV4()

	if err != nil {
		return "", err
	}

	return strings.ReplaceAll(u1.String(), "-", ""), nil
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if err != nil {
		return "", err
	}

	return string(bytes), nil
}
