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
	Name     string `db:"name"`
	UserName string `db:"username"`
	Email    string `db:"email"`
}

type PublicUser struct {
	Uuid     string `json:"uuid"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

type AuthUser struct {
	Id             int           `db:"id"`
	Uuid           string        ` db:"uuid"`
	Name           string        ` db:"name"`
	Username       string        ` db:"username"`
	Email          *mail.Address ` db:"email"`
	HashedPassword []byte
	EmailVerified  bool
	CanLogin       bool
}

// func (user *AuthUser) Address() *mail.Address {
// 	return &mail.Address{Name: user.Name, Address: user.Email}
// }

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
	canLogin bool) *AuthUser {
	return &AuthUser{
		Uuid:           uuid,
		Name:           name,
		Username:       userName,
		Email:          sys.Must(mail.ParseAddress(email)),
		Id:             id,
		HashedPassword: []byte(hashedPassword),
		EmailVerified:  isVerified,
		CanLogin:       canLogin}
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
		Name:     user.Name,
		Username: user.Username,
		Email:    user.Email.Address}
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
