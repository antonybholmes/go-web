package auth

import (
	"database/sql"
	"fmt"
	"net/mail"
	"regexp"

	"github.com/antonybholmes/go-sys"
)

// See https://echo.labstack.com/docs/cookbook/jwt#login

// partially based on https://betterprogramming.pub/hands-on-with-jwt-in-golang-8c986d1bb4c0

const FIND_USER_BY_UUID_SQL string = `SELECT id, name, username, email, password, email_verified, can_signin FROM users WHERE users.uuid = ?`
const FIND_USER_BY_EMAIL_SQL string = `SELECT id, uuid, name, username, password, email_verified, can_signin FROM users WHERE users.email = ?`
const FIND_USER_BY_USERNAME_SQL string = `SELECT id, uuid, name, email, password, email_verified, can_signin FROM users WHERE users.username = ?`
const CREATE_USER_SQL = `INSERT INTO users (uuid, name, username, email, password) VALUES(?, ?, ?, ?, ?)`
const SET_EMAIL_VERIFIED_SQL = `UPDATE users SET email_verified = 1 WHERE users.uuid = ?`
const SET_PASSWORD_SQL = `UPDATE users SET password = ? WHERE users.uuid = ?`
const SET_USERNAME_SQL = `UPDATE users SET username = ? WHERE users.uuid = ?`
const SET_NAME_SQL = `UPDATE users SET name = ? WHERE users.uuid = ?`
const SET_EMAIL_SQL = `UPDATE users SET email = ? WHERE users.uuid = ?`

const MIN_PASSWORD_LENGTH int = 8
const MIN_NAME_LENGTH int = 4

type UserDb struct {
	db                     *sql.DB
	findUserByEmailStmt    *sql.Stmt
	findUserByUsernameStmt *sql.Stmt
	findUserByIdStmt       *sql.Stmt
	createUserStmt         *sql.Stmt
	setEmailVerifiedStmt   *sql.Stmt
	setPasswordStmt        *sql.Stmt
	setUsernameStmt        *sql.Stmt
	setNameStmt            *sql.Stmt
	setEmailStmt           *sql.Stmt
}

var PASSWORD_REGEX *regexp.Regexp
var USERNAME_REGEX *regexp.Regexp
var NAME_REGEX *regexp.Regexp

func init() {
	PASSWORD_REGEX = regexp.MustCompile(`^[A-Za-z\d\@\$\!\%\*\#\?\&\.\~\^\-]*$`)
	USERNAME_REGEX = regexp.MustCompile(`^[\w\-\.@]+$`)
	NAME_REGEX = regexp.MustCompile(`^[\w\- ]+$`)
}

func (userdb *UserDb) Init(file string) error {
	db := sys.Must(sql.Open("sqlite3", file))

	userdb.db = db
	userdb.findUserByEmailStmt = sys.Must(db.Prepare(FIND_USER_BY_EMAIL_SQL))
	userdb.findUserByUsernameStmt = sys.Must(db.Prepare(FIND_USER_BY_USERNAME_SQL))
	userdb.findUserByIdStmt = sys.Must(db.Prepare(FIND_USER_BY_UUID_SQL))
	userdb.createUserStmt = sys.Must(db.Prepare(CREATE_USER_SQL))
	userdb.setEmailVerifiedStmt = sys.Must(db.Prepare(SET_EMAIL_VERIFIED_SQL))
	userdb.setPasswordStmt = sys.Must(db.Prepare(SET_PASSWORD_SQL))
	userdb.setUsernameStmt = sys.Must(db.Prepare(SET_USERNAME_SQL))
	userdb.setNameStmt = sys.Must(db.Prepare(SET_NAME_SQL))
	userdb.setEmailStmt = sys.Must(db.Prepare(SET_EMAIL_SQL))

	return nil
}

func (userdb *UserDb) Close() {
	if userdb.db != nil {
		userdb.db.Close()
	}
}

func (userdb *UserDb) FindUserByEmail(email *mail.Address) (*AuthUser, error) {
	var id int
	var uuid string
	var name string
	var username string
	var hashedPassword string
	var isVerified bool
	var canSignIn bool

	if email == nil {
		return nil, fmt.Errorf("no email address")
	}

	err := userdb.findUserByEmailStmt.QueryRow(email.Address).
		Scan(&id, &uuid, &name, &username, &hashedPassword, &isVerified, &canSignIn)

	if err != nil {
		return nil, err //fmt.Errorf("there was an error with the database query")
	}

	authUser := NewAuthUser(id, uuid, name, username, email.Address, hashedPassword, isVerified, canSignIn)

	return authUser, nil
}

func (userdb *UserDb) FindUserByUsername(username string) (*AuthUser, error) {
	var id int
	var uuid string
	var name string
	var email string
	var hashedPassword string
	var isVerified bool
	var canSignIn bool

	err := CheckUsername(username)

	if err != nil {
		return nil, err
	}

	err = userdb.findUserByUsernameStmt.QueryRow(username).
		Scan(&id, &uuid, &name, &email, &hashedPassword, &isVerified, &canSignIn)

	if err != nil {

		e, err := mail.ParseAddress(username)

		if err != nil {
			return nil, err
		}

		return userdb.FindUserByEmail(e)
	}

	authUser := NewAuthUser(id, uuid, name, username, email, hashedPassword, isVerified, canSignIn)

	return authUser, nil
}

func (userdb *UserDb) FindUserByUuid(uuid string) (*AuthUser, error) {
	var id int
	var name string
	var username string
	var email string
	var hashedPassword string
	var isVerified bool
	var canSignIn bool

	err := userdb.findUserByIdStmt.QueryRow(uuid).
		Scan(&id, &name, &username, &email, &hashedPassword, &isVerified, &canSignIn)

	if err != nil {
		return nil, err //fmt.Errorf("there was an error with the database query")
	}

	authUser := NewAuthUser(id, uuid, name, username, email, hashedPassword, isVerified, canSignIn)

	//log.Printf("find %s %t\n", user.Email, authUser.CheckPasswords(user.Password))

	// check password hash matches hash in database

	return authUser, nil
}

func (userdb *UserDb) SetIsVerified(userId string) error {

	_, err := userdb.setEmailVerifiedStmt.Exec(userId)

	if err != nil {
		return err
	}

	// _, err = userdb.setOtpStmt.Exec("", userId)

	// if err != nil {
	// 	return false
	// }

	return nil
}

func (userdb *UserDb) SetPassword(uuid string, password string) error {
	err := CheckPassword(password)

	if err != nil {
		return err
	}

	hash := HashPassword(password)

	//log.Debug().Msgf("hash:%s:%s:", hash, password)

	_, err = userdb.setPasswordStmt.Exec(hash, uuid)

	if err != nil {
		return fmt.Errorf("could not update password")
	}

	return err
}

func (userdb *UserDb) SetUsername(uuid string, username string) error {

	err := CheckUsername(username)

	if err != nil {
		return err
	}

	_, err = userdb.setUsernameStmt.Exec(username, uuid)

	if err != nil {
		return fmt.Errorf("could not update username")
	}

	return err
}

func (userdb *UserDb) SetName(uuid string, name string) error {
	err := CheckName(name)

	if err != nil {
		return err
	}

	_, err = userdb.setNameStmt.Exec(name, uuid)

	if err != nil {
		return fmt.Errorf("could not update name")
	}

	return err
}

func (userdb *UserDb) SetEmail(uuid string, email string) error {
	address, err := CheckEmail(email)

	if err != nil {
		return err
	}

	return userdb.SetEmailAddress(uuid, address)
}

func (userdb *UserDb) SetEmailAddress(uuid string, address *mail.Address) error {

	_, err := userdb.setEmailStmt.Exec(address.Address, uuid)

	if err != nil {
		return fmt.Errorf("could not update email address")
	}

	return err
}

// func (userdb *UserDb) SetOtp(userId string, otp string) error {
// 	_, err := userdb.setOtpStmt.Exec(otp, userId)

// 	return err
// }

func (userdb *UserDb) CreateUser(user *SignupReq) (*AuthUser, error) {
	err := CheckPassword(user.Password)

	if err != nil {
		return nil, err
	}

	email, err := mail.ParseAddress(user.Email)

	if err != nil {
		return nil, err
	}

	// Check if user exists and if they do, check passwords match.
	// We don't care about errors because errors signify the user
	// doesn't exist so we can continue and make the user
	authUser, err := userdb.FindUserByEmail(email)

	// try to create user if user does not exist
	if err != nil {
		// Create a uuid for the user id
		uuid := Uuid()

		//log.Debug().Msgf("%s %s %s %s %s", user.Name, user.Email, hash, otp)

		_, err = userdb.createUserStmt.Exec(uuid, user.Name, email.Address, email.Address, user.HashedPassword())

		if err != nil {
			return nil, err
		}

		// Call function again to get the user details
		authUser, err = userdb.FindUserByEmail(email)

		if err != nil {
			return nil, err
		}
	} else {
		// user already exists so check if verified

		if authUser.EmailVerified {
			return nil, fmt.Errorf("user already registered:please sign up with another email address")
		} else {
			// if user is not verified, update the password since we assume
			// rightful owner of email address will keep trying until verified
			// this is to stop people blocking creation of accounts by just
			// signing up with email addresses they have no intention of
			// verifying
			err := userdb.SetPassword(authUser.Uuid, user.Password)

			if err != nil {
				return nil, err
			}
		}
	}

	// err = userdb.SetOtp(authUser.UserId, otp)

	// if err != nil {
	// 	return nil, fmt.Errorf("could not set otp")
	// }

	return authUser, nil
}

// Make sure password meets requirements
func CheckPassword(password string) error {
	if password != "" && len(password) < MIN_PASSWORD_LENGTH {
		return fmt.Errorf("password must be at least %d characters", MIN_PASSWORD_LENGTH)
	}

	if !PASSWORD_REGEX.MatchString(password) {
		return fmt.Errorf("invalid password")
	}

	return nil
}

// Make sure password meets requirements
func CheckUsername(username string) error {
	if len(username) < MIN_NAME_LENGTH {
		return fmt.Errorf("username must be at least %d characters", MIN_NAME_LENGTH)
	}

	if !USERNAME_REGEX.MatchString(username) {
		return fmt.Errorf("invalid username")
	}

	return nil
}

// Make sure password meets requirements
func CheckName(name string) error {
	if len(name) < MIN_NAME_LENGTH {
		return fmt.Errorf("name must be at least %d characters", MIN_NAME_LENGTH)
	}

	if !NAME_REGEX.MatchString(name) {
		return fmt.Errorf("invalid name")
	}

	return nil
}

func CheckEmail(email string) (*mail.Address, error) {
	if !USERNAME_REGEX.MatchString(email) {
		return nil, fmt.Errorf("invalid email address")
	}

	address, err := mail.ParseAddress(email)

	if err != nil {
		return nil, fmt.Errorf("could not parse email")
	}

	return address, nil
}
