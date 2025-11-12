package auth

import (
	"fmt"
	"time"

	"github.com/antonybholmes/go-sys"
	"golang.org/x/crypto/bcrypt"
)

type (
	JwtInfo struct {
		UserId string `json:"userId"`
		//Name  string `json:"name"`
		Type TokenType `json:"type"`
		//IpAddr  string `json:"ipAddr"`
		Expires string `json:"expires"`
	}

	User struct {
		FirstName string `db:"first_name"`
		LastName  string `db:"last_name"`
		UserName  string `db:"username"`
		Email     string `db:"email"`
	}

	RBACEntity struct {
		PublicId    string `json:"publicId"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Id          uint   `json:"-"`
	}

	RBACPermission = RBACEntity

	RBACRole struct {
		RBACEntity
		Permissions []*RBACPermission `json:"permissions"`
	}

	RBACGroup struct {
		RBACEntity
		Roles []*RBACRole `json:"roles"`
	}

	AuthUser struct {
		PublicId        string        `json:"publicId"`
		FirstName       string        `json:"firstName"`
		LastName        string        `json:"lastName"`
		Username        string        `json:"username"`
		Email           string        `json:"email"`
		HashedPassword  string        `json:"-"`
		Groups          []*RBACGroup  `json:"groups"`
		ApiKeys         []string      `json:"apiKeys"`
		Id              uint          `json:"id"`
		CreatedAt       time.Duration `json:"-"`
		UpdatedAt       time.Duration `json:"-"`
		EmailVerifiedAt time.Duration `json:"-"`
		IsLocked        bool          `json:"isLocked"`
	}
)

const (
	RoleSuper = "super:*"
	RoleAdmin = "admin:*"
	//RoleUser  = "user:*"
	RoleLogin   = "user:login"
	RoleRdfRead = "rdf:read"

	GroupUser  = "user"
	GroupAdmin = "admin"
	GroupSuper = "super"
	GroupLogin = "login"
)

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

// // Generate a one time code
// func RandCode() string {
// 	return randomstring.CookieFriendlyString(32)
// }

func CheckPasswordsMatch(hashedPassword string, plainPwd string) error {

	// password not set, so no need to check
	if len(hashedPassword) == 0 {
		return nil
	}

	// Since we'll be getting the hashed password from the DB it
	// will be a string so we'll need to convert it to a byte slice

	//log.Printf("comp %s %s\n", string(user.HashedPassword), string(plainPwd))

	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plainPwd))

	if err != nil {
		return fmt.Errorf("passwords do not match")
	}

	return nil
}

func HasSuperRole(roles *sys.StringSet) bool {
	return roles.Has(RoleSuper)
}

func HasAdminRole(roles *sys.StringSet) bool {
	return HasSuperRole(roles) || roles.Has(RoleAdmin)
}

func HasLoginInRole(roles *sys.StringSet) bool {
	return HasAdminRole(roles) || roles.Has(RoleLogin)
}

func FlattenGroups(groups []*RBACGroup) []string {
	ret := make([]string, 0, len(groups)*2)

	for _, g := range groups {
		for _, r := range g.Roles {
			for _, p := range r.Permissions {
				ret = append(ret, fmt.Sprintf("%s:%s:%s", g.Name, r.Name, p.Name))
			}
		}
	}

	return ret
}
