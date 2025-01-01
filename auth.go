package auth

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/antonybholmes/go-sys"
	"github.com/google/uuid"
	gonanoid "github.com/matoous/go-nanoid/v2"
	"github.com/xyproto/randomstring"
	"golang.org/x/crypto/bcrypt"
)

const (
	MAX_AGE_YEAR_SECS    = 31536000
	MAX_AGE_30_DAYS_SECS = 2592000
	MAX_AGE_7_DAYS_SECS  = 604800 //86400 * 7
	MAX_AGE_DAY_SECS     = 86400
)

const (
	ROLE_SUPER  = "Super"
	ROLE_ADMIN  = "Admin"
	ROLE_USER   = "User"
	ROLE_SIGNIN = "Signin"
	ROLE_RDF    = "RDF"
)

type UrlReq struct {
	Url string `json:"url"`
}

type UrlCallbackReq struct {
	// the url that should form the email link in any emails that are sent
	CallbackUrl string `json:"callbackUrl"`
	// The url the callback url should redirect to once it completes
	VisitUrl string `json:"visitUrl"`
}

type User struct {
	FirstName string `db:"first_name"`
	LastName  string `db:"last_name"`
	UserName  string `db:"username"`
	Email     string `db:"email"`
}

type Permission struct {
	Uuid        string `json:"uuid"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Id          uint   `json:"-"`
}

type Role struct {
	Uuid        string `json:"uuid"`
	Name        string `json:"name"`
	Description string `json:"description"`
	//Permissions []Permission `json:"permissions"`
	Id uint `json:"-" db:"id"`
}

type AuthUser struct {
	Uuid            string        `json:"uuid"`
	FirstName       string        `json:"firstName"`
	LastName        string        `json:"lastName"`
	Username        string        `json:"username"`
	Email           string        `json:"email"`
	HashedPassword  string        `json:"-"`
	Roles           []string      `json:"roles"`
	ApiKeys         []string      `json:"apiKeys"`
	Id              uint          `json:"id"`
	CreatedAt       time.Duration `json:"-"`
	UpdatedAt       time.Duration `json:"-"`
	EmailVerifiedAt time.Duration `json:"-"`
	IsLocked        bool          `json:"isLocked"`
}

// The admin view adds roles to each user as it is assumed this
// will be used for listing users for an admin dashboard where you
// may need to know every user's roles. A standard user view does not
// include roles and these are instead expected to be derived from
// the access jwt assigned to the user since this contains their
// encoded roles and is more resilient to tampering
// type AuthUserAdminView struct {
// 	Roles []string `json:"roles" db:"role"`
// 	AuthUser
// }

// func (user *AuthUser) Address() *mail.Address {
// 	return &mail.Address{Name: user.Name, Address: user.Email}
// }

func init() {
	randomstring.Seed()
}

// func NewAuthUser(
// 	id uint,
// 	publicId string,
// 	firstName string,
// 	lastName string,
// 	userName string,
// 	email string,
// 	hashedPassword string,
// 	isVerified bool,
// 	//canSignIn bool,
// 	updated uint64) *AuthUser {
// 	return &AuthUser{
// 		Id:              id,
// 		PublicId:        publicId,
// 		FirstName:       firstName,
// 		LastName:        lastName,
// 		Username:        userName,
// 		Email:           email,
// 		HashedPassword:  hashedPassword,
// 		EmailIsVerified: isVerified,
// 		//CanSignIn:      canSignIn,
// 		UpdatedAt: updated}
// }

func (user *AuthUser) CheckPasswordsMatch(plainPwd string) error {
	return CheckPasswordsMatch(user.HashedPassword, plainPwd)
}

// func (user *AuthUser) IsSuper() bool {
// 	return IsSuper(user.Roles)
// }

// func (user *AuthUser) IsAdmin() bool {
// 	return IsAdmin(user.Roles)
// }

// // Returns true if user is an admin or super, or is a member of
// // the login group
// func (user *AuthUser) CanLogin() bool {
// 	return CanLogin(user.Roles)
// }

func IsSuper(roles string) bool {
	return strings.Contains(roles, ROLE_SUPER)
}

func IsAdmin(roles string) bool {
	return IsSuper(roles) || strings.Contains(roles, ROLE_ADMIN)

}

func CanSignin(roles string) bool {
	return IsAdmin(roles) || strings.Contains(roles, ROLE_SIGNIN)
}

// // Generate a one time code
// func RandCode() string {
// 	return randomstring.CookieFriendlyString(32)
// }

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

// Only to be used for database update events.
func CreateOTP(user *AuthUser) string {
	return HashPassword(strconv.FormatInt(user.UpdatedAt.Nanoseconds(), 10))

}

func CheckOTPValid(user *AuthUser, otp string) error {
	err := CheckPasswordsMatch(otp, strconv.FormatInt(user.UpdatedAt.Nanoseconds(), 10))

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

func IsValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}
