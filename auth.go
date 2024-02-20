package auth

import (
	"database/sql"
	"strings"

	"github.com/antonybholmes/go-mailer"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
	"github.com/xyproto/randomstring"
	"golang.org/x/crypto/bcrypt"
)

// See https://echo.labstack.com/docs/cookbook/jwt#login

// partially based on https://betterprogramming.pub/hands-on-with-jwt-in-golang-8c986d1bb4c0

const FIND_USER_BY_ID_SQL string = `SELECT id, user_id, name, email, password, is_verified, can_auth FROM users WHERE users.user_id = ?`
const FIND_USER_BY_EMAIL_SQL string = `SELECT id, user_id, name, email, password, is_verified, can_auth FROM users WHERE users.email = ?`
const CREATE_USER_SQL = `INSERT INTO users (user_id, name, email, password) VALUES(?, ?, ?, ?)`
const SET_IS_VERIFIED_SQL = `UPDATE users SET is_verified = 1 WHERE users.user_id = ?`
const SET_PASSWORD_SQL = `UPDATE users SET password = ? WHERE users.user_id = ?`

//const SET_OTP_SQL = `UPDATE users SET otp = ? WHERE users.user_id = ?`

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

type UserDb struct {
	db                  *sql.DB
	findUserByEmailStmt *sql.Stmt
	findUserByIdStmt    *sql.Stmt
	createUserStmt      *sql.Stmt
	setIsVerifiedStmt   *sql.Stmt
	setPasswordStmt     *sql.Stmt
	//setOtpStmt          *sql.Stmt
}

func NewUserDb(file string) (*UserDb, error) {
	db, err := sql.Open("sqlite3", file)

	if err != nil {
		return nil, err
	}

	findUserByEmailStmt, err := db.Prepare(FIND_USER_BY_EMAIL_SQL)

	if err != nil {
		return nil, err
	}

	findUserByIdStmt, err := db.Prepare(FIND_USER_BY_ID_SQL)

	if err != nil {
		return nil, err
	}

	createUserStmt, err := db.Prepare(CREATE_USER_SQL)

	if err != nil {
		return nil, err
	}

	setIsVerifiedStmt, err := db.Prepare(SET_IS_VERIFIED_SQL)

	if err != nil {
		return nil, err
	}

	setPasswordStmt, err := db.Prepare(SET_PASSWORD_SQL)

	if err != nil {
		return nil, err
	}

	// setOtpStmt, err := db.Prepare(SET_OTP_SQL)

	// if err != nil {
	// 	return nil, err
	// }

	return &UserDb{db, findUserByEmailStmt, findUserByIdStmt, createUserStmt, setIsVerifiedStmt, setPasswordStmt}, nil
}

func (userdb *UserDb) Close() {
	userdb.db.Close()
}

func (userdb *UserDb) FindUserByEmail(email string) (*AuthUser, error) {
	var id int
	var userId string
	var name string
	var hashedPassword string
	var isVerified bool
	var canAuth bool

	err := userdb.findUserByEmailStmt.QueryRow(email).Scan(&id, &userId, &name, &email, &hashedPassword, &isVerified, &canAuth)

	if err != nil {
		return nil, err //fmt.Errorf("there was an error with the database query")
	}

	authUser := NewAuthUser(id, userId, name, email, hashedPassword, isVerified, canAuth)

	//log.Printf("find %s %t\n", user.Email, authUser.CheckPasswords(user.Password))

	// check password hash matches hash in database

	return authUser, nil
}

func (userdb *UserDb) FindUserById(userId string) (*AuthUser, error) {
	var id int
	var name string
	var email string
	var hashedPassword string
	var isVerified bool
	var canAuth bool

	err := userdb.findUserByIdStmt.QueryRow(userId).Scan(&id, &userId, &name, &email, &hashedPassword, &isVerified, &canAuth)

	if err != nil {
		return nil, err //fmt.Errorf("there was an error with the database query")
	}

	authUser := NewAuthUser(id, userId, name, email, hashedPassword, isVerified, canAuth)

	//log.Printf("find %s %t\n", user.Email, authUser.CheckPasswords(user.Password))

	// check password hash matches hash in database

	return authUser, nil
}

func (userdb *UserDb) SetIsVerified(userId string) error {
	log.Debug().Msgf("verify %s", userId)
	_, err := userdb.setIsVerifiedStmt.Exec(userId)

	if err != nil {
		return err
	}

	// _, err = userdb.setOtpStmt.Exec("", userId)

	// if err != nil {
	// 	return false
	// }

	return nil
}

func (userdb *UserDb) SetPassword(userId string, password string) error {
	hash, err := HashPassword(password)

	if err != nil {
		return err
	}

	_, err = userdb.setPasswordStmt.Exec(hash, userId)

	return err
}

// func (userdb *UserDb) SetOtp(userId string, otp string) error {
// 	_, err := userdb.setOtpStmt.Exec(otp, userId)

// 	return err
// }

func (userdb *UserDb) CreateUser(user *SignupReq) (*AuthUser, error) {
	// Check if user exists and if they do, check passwords match.
	// We don't care about errors because errors signify the user
	// doesn't exist so we can continue and make the user
	authUser, err := userdb.FindUserByEmail(user.Email)

	// try to create user if user does not exist
	if err != nil {
		// Create a uuid for the user id
		uuid, err := Uuid()

		if err != nil {
			return nil, err
		}

		hash, err := user.Hash()

		if err != nil {
			return nil, err
		}

		//log.Debug().Msgf("%s %s %s %s %s", user.Name, user.Email, hash, otp)

		_, err = userdb.createUserStmt.Exec(uuid, user.Name, user.Email, hash)

		if err != nil {
			return nil, err
		}

		// Call function again to get the user details
		authUser, err = userdb.FindUserByEmail(user.Email)

		if err != nil {
			return nil, err
		}
	}

	// err = userdb.SetOtp(authUser.UserId, otp)

	// if err != nil {
	// 	return nil, fmt.Errorf("could not set otp")
	// }

	return authUser, nil
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
