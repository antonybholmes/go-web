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

const FIND_USER_BY_UUID_SQL string = `SELECT id, name, username, email, password, email_verified, can_auth FROM users WHERE users.uuid = ?`
const FIND_USER_BY_EMAIL_SQL string = `SELECT id, uuid, name, username, password, email_verified, can_auth FROM users WHERE users.email = ?`
const FIND_USER_BY_USERNAME_SQL string = `SELECT id, uuid, name, email, password, email_verified, can_auth FROM users WHERE users.username = ?`
const CREATE_USER_SQL = `INSERT INTO users (uuid, name, username, email, password) VALUES(?, ?, ?, ?, ?)`
const SET_EMAIL_VERIFIED_SQL = `UPDATE users SET email_verified = 1 WHERE users.uuid = ?`
const SET_PASSWORD_SQL = `UPDATE users SET password = ? WHERE users.uuid = ?`
const SET_USERNAME_SQL = `UPDATE users SET username = ? WHERE users.uuid = ?`
const SET_NAME_SQL = `UPDATE users SET name = ? WHERE users.uuid = ?`

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
	userNamePattern        *regexp.Regexp
	namePattern            *regexp.Regexp
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
	userdb.userNamePattern = sys.Must(regexp.Compile(`^[\w\-\.@]+$`))
	userdb.namePattern = sys.Must(regexp.Compile(`^[\w\- ]+$`))

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
	var canAuth bool

	err := userdb.findUserByEmailStmt.QueryRow(email.Address).
		Scan(&id, &uuid, &name, &username, &hashedPassword, &isVerified, &canAuth)

	if err != nil {
		return nil, err //fmt.Errorf("there was an error with the database query")
	}

	authUser := NewAuthUser(id, uuid, name, username, email.Address, hashedPassword, isVerified, canAuth)

	return authUser, nil
}

func (userdb *UserDb) FindUserByUsername(username string) (*AuthUser, error) {
	var id int
	var uuid string
	var name string
	var email string
	var hashedPassword string
	var isVerified bool
	var canAuth bool

	match := userdb.userNamePattern.MatchString(username)

	if !match {
		return nil, fmt.Errorf("invalid username")
	}

	err := userdb.findUserByUsernameStmt.QueryRow(username).
		Scan(&id, &uuid, &name, &email, &hashedPassword, &isVerified, &canAuth)

	if err != nil {
		return nil, err //fmt.Errorf("there was an error with the database query")
	}

	authUser := NewAuthUser(id, uuid, name, username, email, hashedPassword, isVerified, canAuth)

	return authUser, nil
}

func (userdb *UserDb) FindUserByUuid(uuid string) (*AuthUser, error) {
	var id int
	var name string
	var username string
	var email string
	var hashedPassword string
	var isVerified bool
	var canAuth bool

	err := userdb.findUserByIdStmt.QueryRow(uuid).
		Scan(&id, &name, &username, &email, &hashedPassword, &isVerified, &canAuth)

	if err != nil {
		return nil, err //fmt.Errorf("there was an error with the database query")
	}

	authUser := NewAuthUser(id, uuid, name, username, email, hashedPassword, isVerified, canAuth)

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

func (userdb *UserDb) SetPassword(userId string, password string) error {
	hash := HashPassword(password)

	_, err := userdb.setPasswordStmt.Exec(hash, userId)

	return err
}

func (userdb *UserDb) SetUsername(userId string, username string) error {

	if !userdb.userNamePattern.MatchString(username) {
		return fmt.Errorf("invalid username")
	}

	_, err := userdb.setUsernameStmt.Exec(username, userId)

	return err
}

func (userdb *UserDb) SetName(userId string, name string) error {

	if !userdb.namePattern.MatchString(name) {
		return fmt.Errorf("invalid name")
	}

	_, err := userdb.setNameStmt.Exec(name, userId)

	return err
}

// func (userdb *UserDb) SetOtp(userId string, otp string) error {
// 	_, err := userdb.setOtpStmt.Exec(otp, userId)

// 	return err
// }

func (userdb *UserDb) CreateUser(user *SignupReq) (*AuthUser, error) {

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

		_, err = userdb.createUserStmt.Exec(uuid, user.Name, email.Address, email.Address, user.Hash())

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
			return nil, fmt.Errorf("you cannot sign up with this email address")
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
