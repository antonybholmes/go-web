package auth

import (
	"net/mail"

	"github.com/antonybholmes/go-sys"
	"github.com/google/uuid"
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
	Name     string `json:"name" db:"name"`
	UserName string `json:"userName" db:"username"`
	Email    string `json:"email" db:"email"`
}

type PublicUser struct {
	Uuid string `json:"uuid" db:"uuid"`
	User
}

type AuthUser struct {
	PublicUser
	Id             int    `json:"int"`
	HashedPassword []byte `json:"hashedPassword"`
	IsVerified     bool   `json:"isVerified"`
	CanAuth        bool   `json:"canAuth"`
}

func (user *AuthUser) Address() *mail.Address {
	return &mail.Address{Name: user.Name, Address: user.Email}
}

func init() {
	randomstring.Seed()
}

func NewAuthUser(id int,
	uuid string,
	name string,
	userName string,
	email string,
	hashedPassword string,
	isVerified bool,
	canAuth bool) *AuthUser {
	return &AuthUser{
		PublicUser: PublicUser{
			Uuid: uuid,
			User: User{Name: name, UserName: userName, Email: email}},
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

// Returns user details suitable for a web app to display
func (user *AuthUser) ToPublicUser() *PublicUser {
	return &PublicUser{Uuid: user.Uuid,
		User: User{Name: user.Name, Email: user.Email}}
}

// Generate a one time code
func RandCode() string {
	return randomstring.CookieFriendlyString(32)
}

func Uuid() string {
	return uuid.New().String() // strings.ReplaceAll(u1.String(), "-", ""), nil
}

func HashPassword(password string) string {
	return string(sys.Must(bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)))
}
