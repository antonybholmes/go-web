package auth

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/antonybholmes/go-mailer"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
	"github.com/xyproto/randomstring"
	"golang.org/x/crypto/bcrypt"
)

// See https://echo.labstack.com/docs/cookbook/jwt#login

// partially based on https://betterprogramming.pub/hands-on-with-jwt-in-golang-8c986d1bb4c0

const JWT_TOKEN_EXPIRES_HOURS time.Duration = 24
const INVALID_JWT_MESSAGE string = "Invalid JWT"
const FIND_USER_BY_ID_SQL string = `SELECT id, user_id, name, email, password, is_verified, otp FROM users WHERE users.user_id = ?`
const FIND_USER_BY_EMAIL_SQL string = `SELECT id, user_id, name, email, password, is_verified, otp FROM users WHERE users.email = ?`
const CREATE_USER_SQL = `INSERT INTO users (user_id, name, email, password, otp) VALUES(?, ?, ?, ?, ?)`
const SET_IS_VERIFIED_SQL = `UPDATE users SET is_verified = 1 WHERE users.user_id = ?`
const CLEAR_OTP_SQL = `UPDATE users SET otp = "" WHERE users.user_id = ?`

type UrlReq struct {
	Url string `json:"url"`
}

type UrlCallbackReq struct {
	// the url that should form the email link in any emails that are sent
	CallbackUrl string `json:"callbackUrl"`
	// The url the callback url should redirect to once it completes
	Url string `json:"url"`
}

type LoginReq struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	UrlCallbackReq
}

type User struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type LoginUser struct {
	User
	Password []byte `json:"password"`
}

func (user *LoginUser) String() string {
	return fmt.Sprintf("%s:%s:%s", user.Name, user.Email, user.Password)
}

func NewLoginUser(name string, email string, password string) *LoginUser {
	return &LoginUser{User: User{Name: name, Email: email}, Password: []byte(password)}
}

func LoginUserFromReq(req *LoginReq) *LoginUser {
	return NewLoginUser(req.Name, req.Email, req.Password)
}

func (user *LoginUser) HashPassword() ([]byte, error) {
	bytes, err := bcrypt.GenerateFromPassword(user.Password, bcrypt.DefaultCost)

	if err != nil {
		return nil, err
	}

	return bytes, nil
}

func (user *LoginUser) Mailbox() *mailer.Mailbox {
	return mailer.NewMailbox(user.Name, user.Email)
}

type AuthUser struct {
	User
	Id             int    `json:"int"`
	UserId         string `json:"user_id"`
	HashedPassword []byte `json:"hashed_password"`
	IsVerified     bool   `json:"isVerified"`
	OTP            string `json:"otp"`
}

func (user *AuthUser) Mailbox() *mailer.Mailbox {
	return mailer.NewMailbox(user.Name, user.Email)
}

func init() {
	randomstring.Seed()
}

func NewAuthUser(id int, userId string, name string, email string, hashedPassword string, isVerified bool, otp string) *AuthUser {
	return &AuthUser{User: User{Name: name, Email: email},
		Id:             id,
		UserId:         userId,
		HashedPassword: []byte(hashedPassword),
		IsVerified:     isVerified,
		OTP:            otp}
}

func NewAuthUserFromLogin(id int, userId string, hashedPassword string, isVerified bool, otp string, user *LoginUser) *AuthUser {
	return &AuthUser{User: User{Name: user.Name, Email: user.Email},
		Id:             id,
		UserId:         userId,
		HashedPassword: []byte(hashedPassword),
		IsVerified:     isVerified,
		OTP:            otp}
}

func (user *AuthUser) CheckPasswords(plainPwd []byte) bool {
	// Since we'll be getting the hashed password from the DB it
	// will be a string so we'll need to convert it to a byte slice

	//log.Printf("comp %s %s\n", string(user.HashedPassword), string(plainPwd))

	err := bcrypt.CompareHashAndPassword(user.HashedPassword, plainPwd)

	return err == nil
}

type UserDb struct {
	db                  *sql.DB
	findUserByEmailStmt *sql.Stmt
	findUserByIdStmt    *sql.Stmt
	createUserStmt      *sql.Stmt
	setIsVerifiedStmt   *sql.Stmt
	clearOtpStmt        *sql.Stmt
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

	clearOtpStmt, err := db.Prepare(SET_IS_VERIFIED_SQL)

	if err != nil {
		return nil, err
	}

	return &UserDb{db, findUserByEmailStmt, findUserByIdStmt, createUserStmt, setIsVerifiedStmt, clearOtpStmt}, nil
}

func (userdb *UserDb) Close() {
	userdb.db.Close()
}

func (userdb *UserDb) FindUserByEmail(user *LoginUser) (*AuthUser, error) {
	var id int
	var userId string
	var name string
	var email string
	var hashedPassword string
	var isVerified bool
	var otp string

	log.Debug().Msgf("%s here", user.Email)

	err := userdb.findUserByEmailStmt.QueryRow(user.Email).Scan(&id, &userId, &name, &email, &hashedPassword, &isVerified, &otp)

	if err != nil {
		log.Debug().Msgf("%s ee", err)
		return nil, err //fmt.Errorf("there was an error with the database query")
	}

	log.Debug().Msgf("%s here2", user.Email)

	authUser := NewAuthUserFromLogin(id, userId, hashedPassword, isVerified, otp, user)

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
	var otp string

	log.Debug().Msgf("%s here", userId)

	err := userdb.findUserByIdStmt.QueryRow(userId).Scan(&id, &userId, &name, &email, &hashedPassword, &isVerified, &otp)

	if err != nil {
		log.Debug().Msgf("%s ee", err)
		return nil, err //fmt.Errorf("there was an error with the database query")
	}

	authUser := NewAuthUser(id, userId, name, email, hashedPassword, isVerified, otp)

	//log.Printf("find %s %t\n", user.Email, authUser.CheckPasswords(user.Password))

	// check password hash matches hash in database

	return authUser, nil
}

func (userdb *UserDb) SetIsVerified(userId string) bool {
	log.Debug().Msgf("verify %s", userId)
	_, err := userdb.setIsVerifiedStmt.Exec(userId)

	if err != nil {
		return false
	}

	// _, err = userdb.clearOtpStmt.Exec(userId)

	// if err != nil {
	// 	return false
	// }

	return true
}

func (userdb *UserDb) CreateUser(user *LoginUser, otp string) (*AuthUser, error) {

	// Check if user exists and if they do, check passwords match.
	// We don't care about errors because errors signify the user
	// doesn't exist so we can continue and make the user
	authUser, _ := userdb.FindUserByEmail(user)

	if authUser != nil {
		return nil, fmt.Errorf("user already exists")
	}

	// Create a uuid for the user id
	u1, err := uuid.NewV4()

	if err != nil {
		return nil, err
	}

	uuid := u1.String()

	uuid = strings.ReplaceAll(uuid, "-", "")

	hash, err := user.HashPassword()

	if err != nil {
		return nil, err
	}

	log.Debug().Msgf("%s %s %s %s %s", uuid, user.Name, user.Email, hash, otp)

	_, err = userdb.createUserStmt.Exec(uuid, user.Name, user.Email, hash, otp)

	if err != nil {
		return nil, err
	}

	// Call function again to get the user details
	authUser, err = userdb.FindUserByEmail(user)

	if err != nil {
		return nil, err
	}

	return authUser, nil
}

// Generate a one time code
func OTP() string {
	return randomstring.CookieFriendlyString(32)
}
