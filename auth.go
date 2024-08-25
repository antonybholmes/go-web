package auth

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/antonybholmes/go-sys"
	gonanoid "github.com/matoous/go-nanoid"
	"github.com/xyproto/randomstring"
	"golang.org/x/crypto/bcrypt"
)

const (
	ROLE_SUPER = "Super"
	ROLE_ADMIN = "Admin"
	ROLE_LOGIN = "Login"
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
	FirstName string `db:"first_name"`
	LastName  string `db:"last_name"`
	UserName  string `db:"username"`
	Email     string `db:"email"`
}

type Permission struct {
	Id          string `json:"-" db:"id"`
	PublicId    string `json:"publicId" db:"public_id"`
	Name        string `json:"name" db:"name"`
	Description string `json:"description" db:"description"`
}

type Role struct {
	PublicId    string       `json:"publicId" db:"public_id"`
	Name        string       `json:"name"`
	Description string       `json:"description" db:"description"`
	Permissions []Permission `json:"permissions"`
	Id          int          `json:"-" db:"id"`
}

// type PublicRole struct {
// 	Name        string   `json:"name"`
// 	Permissions []string `json:"permissions"`
// }

// type PublicUser struct {
// 	Uuid      string `json:"uuid"`
// 	FirstName string `json:"firstName"`
// 	LastName  string `json:"lastName"`
// 	Username  string `json:"username"`
// 	Email     string `json:"email"`
// }

type AuthUser struct {
	PublicId        string   `json:"publicId" db:"public_id"`
	FirstName       string   `json:"firstName" db:"first_name"`
	LastName        string   `json:"lastName" db:"last_name"`
	Username        string   `json:"username" db:"username"`
	Email           string   `json:"email" db:"email"`
	HashedPassword  string   `json:"-"`
	Roles           []string `json:"roles" db:"role"`
	Id              uint     `json:"-"`
	Updated         uint64   `json:"-"`
	EmailIsVerified bool     `json:"-"`
}

// func (user *AuthUser) Address() *mail.Address {
// 	return &mail.Address{Name: user.Name, Address: user.Email}
// }

func init() {
	randomstring.Seed()
}

func NewAuthUser(
	id uint,
	uuid string,
	firstName string,
	lastName string,
	userName string,
	email string,
	hashedPassword string,
	isVerified bool,
	//canSignIn bool,
	updated uint64) *AuthUser {
	return &AuthUser{
		Id:              id,
		PublicId:        uuid,
		FirstName:       firstName,
		LastName:        lastName,
		Username:        userName,
		Email:           email,
		HashedPassword:  hashedPassword,
		EmailIsVerified: isVerified,
		//CanSignIn:      canSignIn,
		Updated: updated}
}

func (user *AuthUser) CheckPasswordsMatch(plainPwd string) error {
	return CheckPasswordsMatch(user.HashedPassword, plainPwd)
}

func (user *AuthUser) IsSuper() bool {
	return IsSuper(user.Roles)
}

func (user *AuthUser) IsAdmin() bool {
	return IsAdmin(user.Roles)
}

// Returns true if user is an admin or super, or is a member of
// the login group
func (user *AuthUser) CanLogin() bool {
	return CanLogin(user.Roles)
}

func IsSuper(roles []string) bool {
	for _, role := range roles {
		if strings.Contains(role, ROLE_SUPER) {
			return true
		}
	}

	return false
}

func IsAdmin(roles []string) bool {
	if IsSuper(roles) {
		return true
	}

	for _, role := range roles {
		if strings.Contains(role, ROLE_ADMIN) {
			return true
		}
	}

	return false

}

func CanLogin(roles []string) bool {
	if IsAdmin(roles) {
		return true
	}

	for _, role := range roles {
		if strings.Contains(role, ROLE_LOGIN) {
			return true
		}
	}

	return false

}

// Returns user details suitable for a web app to display
// func (user *AuthUser) ToPublicUser() *PublicUser {
// 	log.Debug().Msgf("here")
// 	return &PublicUser{Uuid: user.Uuid,
// 		FirstName: user.FirstName,
// 		LastName:  user.LastName,
// 		Username:  user.Username,
// 		Email:     user.Email.Address}
// }

// Generate a one time code
func RandCode() string {
	return randomstring.CookieFriendlyString(32)
}

func HashPassword(password string) string {
	return string(sys.Must(bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)))
}

func CheckPasswordsMatch(hashedPassword string, plainPwd string) error {

	// Since we'll be getting the hashed password from the DB it
	// will be a string so we'll need to convert it to a byte slice

	//log.Printf("comp %s %s\n", string(user.HashedPassword), string(plainPwd))

	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plainPwd))

	if err != nil {
		return fmt.Errorf("passwords do not match")
	}

	return nil
}

func CreateOtp(user *AuthUser) string {
	return HashPassword(strconv.FormatUint(user.Updated, 10))

}

func CheckOtpValid(user *AuthUser, otp string) error {
	err := CheckPasswordsMatch(otp, strconv.FormatUint(user.Updated, 10))

	if err != nil {
		return fmt.Errorf("one time code has expired")
	}

	return nil
}

func NanoId() string {
	// good enough for Planetscale https://planetscale.com/blog/why-we-chose-nanoids-for-planetscales-api
	id, err := gonanoid.Generate("0123456789abcdefghijklmnopqrstuvwxyz", 12)

	if err != nil {
		id = ""
	}

	return id
}
