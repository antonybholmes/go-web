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
		Email     string `db:"email"`
		UserName  string `db:"username"`
		FirstName string `db:"first_name"`
		LastName  string `db:"last_name"`
	}

	RBACEntity struct {
		Id          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
	}

	RBACPermission struct {
		RBACEntity
		Resource string `json:"resource"`
		Action   string `json:"action"`
	}

	RBACRole struct {
		RBACEntity
		Permissions []*RBACPermission `json:"permissions"`
	}

	RBACGroup struct {
		RBACEntity
		Roles []*RBACRole `json:"roles"`
	}

	AuthProvider struct {
		Id        string     `json:"id"`
		Name      string     `json:"name"`
		UpdatedAt *time.Time `json:"updatedAt"`
	}

	UserAuthProvider struct {
		Id           string        `json:"id"`
		UserId       *AuthUser     `json:"user"`
		AuthProvider *AuthProvider `json:"authProvider"`
	}

	PublicKey struct {
		Id   string `json:"id"`
		Name string `json:"name"`
		Key  string `json:"key"`
	}

	AuthUser struct {
		Id              string          `json:"id"`
		Name            string          `json:"name"`
		Username        string          `json:"username"`
		Email           string          `json:"email"`
		HashedPassword  string          `json:"-"`
		Groups          []*RBACGroup    `json:"groups"`
		AuthProviders   []*AuthProvider `json:"authProviders"`
		ApiKeys         []string        `json:"apiKeys"`
		PublicKeys      []*PublicKey    `json:"publicKeys"`
		CreatedAt       *time.Time      `json:"createdAt"`
		UpdatedAt       *time.Time      `json:"updatedAt"`
		EmailVerifiedAt *time.Time      `json:"-"`
		IsLocked        bool            `json:"isLocked"`
	}
)

const (
	RolePermissionSep = "::"
	ResourceActionSep = ":"

	RoleSuper = "root::*:*"
	RoleAdmin = "admin::*:*"
	//RoleUser  = "user:*"
	RoleWebLogin = "login::web:login"
	//RoleRdfRead  = "rdf:read:*"

	AdminPermission    = "*:*"
	WebLoginPermission = "web:login"

	GroupUser  = "users"
	GroupAdmin = "admins"
	GroupSuper = "superusers"
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

// func userHasRole(groups []*RBACGroup, f func(roles *sys.StringSet) bool) bool {
// 	roles := sys.NewStringSet()

// 	for _, g := range groups {
// 		for _, r := range g.Roles {
// 			roles.Add(r.Name)
// 		}
// 	}

// 	return f(roles)
// }

func userHasRole(groups []*RBACGroup, f func(roles *sys.StringSet) bool) bool {
	permissions := sys.NewStringSet()

	for _, g := range groups {
		for _, r := range g.Roles {
			for _, p := range r.Permissions {
				// of the form role::resource:action
				permissions.Add(r.Name + RolePermissionSep + p.Resource + ResourceActionSep + p.Action)
			}
		}
	}

	return f(permissions)
}

func UserHasSuperRole(user *AuthUser) bool {
	return userHasRole(user.Groups, func(roles *sys.StringSet) bool {
		return roles.Has(RoleSuper)
	})
}

func UserHasAdminRole(user *AuthUser) bool {
	return userHasRole(user.Groups, func(roles *sys.StringSet) bool {
		return roles.Has(RoleAdmin) || roles.Has(RoleSuper)
	})
}

func UserHasWebLoginInRole(user *AuthUser) bool {
	return userHasRole(user.Groups, func(roles *sys.StringSet) bool {
		return roles.Has(RoleWebLogin)
	})
}

// func FlattenGroups(groups []*RBACGroup) []string {
// 	ret := make([]string, 0, len(groups))

// 	for _, g := range groups {
// 		for _, r := range g.Roles {
// 			for _, p := range r.Permissions {
// 				ret = append(ret, fmt.Sprintf("%s::%s::%s:%s", g.Name, r.Name, p.Resource, p.Action))
// 			}
// 		}
// 	}

// 	return ret
// }

// Return just the unique role:permission strings from groups
// func FlattenRolePermissionsFromGroups(groups []*RBACGroup) *sys.StringSet {
// 	roles := sys.NewStringSet()

// 	for _, g := range groups {
// 		for _, r := range g.Roles {
// 			for _, p := range r.Permissions {
// 				roles.Add(FormatRole(r.Name, p.Resource, p.Action))
// 			}
// 		}
// 	}

// 	//ret := make([]string, 0, roles.Len())

// 	//ret = append(ret, roles.Keys()...)

// 	//slices.Sort(ret)

// 	return roles //.Keys()
// }

// Simplify user groups to role permissions for use in tokens etc which
// don't need the full group structure but just the roles and permissions
func GetRolesFromUser(user *AuthUser) []*Role {
	ret := make([]*Role, 0, len(user.Groups))

	used := sys.NewStringSet()

	for _, g := range user.Groups {
		for _, r := range g.Roles {
			// skip if we have already added this role
			if used.Has(r.Id) {
				continue
			}

			used.Add(r.Id)

			rp := &Role{
				Name:        r.Name,
				Permissions: make([]*Permission, 0, len(r.Permissions)),
			}

			for _, p := range r.Permissions {
				rp.Permissions = append(rp.Permissions, &Permission{
					Resource: p.Resource,
					Action:   p.Action,
				})
			}

			ret = append(ret, rp)
		}
	}

	return ret
}
