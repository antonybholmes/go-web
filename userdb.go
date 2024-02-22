package auth

import (
	"database/sql"
	"net/mail"
)

// See https://echo.labstack.com/docs/cookbook/jwt#login

// partially based on https://betterprogramming.pub/hands-on-with-jwt-in-golang-8c986d1bb4c0

const FIND_USER_BY_UUID_SQL string = `SELECT id, name, username, email, password, is_verified, can_auth FROM users WHERE users.uuid = ?`
const FIND_USER_BY_EMAIL_SQL string = `SELECT id, uuid, name, username, password, is_verified, can_auth FROM users WHERE users.email = ?`
const FIND_USER_BY_USERNAME_SQL string = `SELECT id, uuid, name, email, password, is_verified, can_auth FROM users WHERE users.username = ?`
const CREATE_USER_SQL = `INSERT INTO users (uuid, name, username, email, password) VALUES(?, ?, ?, ?, ?)`
const SET_IS_VERIFIED_SQL = `UPDATE users SET is_verified = 1 WHERE users.user_id = ?`
const SET_PASSWORD_SQL = `UPDATE users SET password = ? WHERE users.user_id = ?`

type UserDb struct {
	db                     *sql.DB
	findUserByEmailStmt    *sql.Stmt
	findUserByUsernameStmt *sql.Stmt
	findUserByIdStmt       *sql.Stmt
	createUserStmt         *sql.Stmt
	setIsVerifiedStmt      *sql.Stmt
	setPasswordStmt        *sql.Stmt
	//setOtpStmt          *sql.Stmt
}

func (userdb *UserDb) Init(file string) error {
	db, err := sql.Open("sqlite3", file)

	if err != nil {
		return err
	}

	findUserByEmailStmt, err := db.Prepare(FIND_USER_BY_EMAIL_SQL)

	if err != nil {
		return err
	}

	findUserByUsernameStmt, err := db.Prepare(FIND_USER_BY_USERNAME_SQL)

	if err != nil {
		return err
	}

	findUserByUuidStmt, err := db.Prepare(FIND_USER_BY_UUID_SQL)

	if err != nil {
		return err
	}

	createUserStmt, err := db.Prepare(CREATE_USER_SQL)

	if err != nil {
		return err
	}

	setIsVerifiedStmt, err := db.Prepare(SET_IS_VERIFIED_SQL)

	if err != nil {
		return err
	}

	setPasswordStmt, err := db.Prepare(SET_PASSWORD_SQL)

	if err != nil {
		return err
	}

	userdb.db = db
	userdb.findUserByEmailStmt = findUserByEmailStmt
	userdb.findUserByUsernameStmt = findUserByUsernameStmt
	userdb.findUserByIdStmt = findUserByUuidStmt
	userdb.createUserStmt = createUserStmt
	userdb.setIsVerifiedStmt = setIsVerifiedStmt
	userdb.setPasswordStmt = setPasswordStmt

	return nil
}

func (userdb *UserDb) Close() {
	if userdb.db != nil {
		userdb.db.Close()
	}
}

func (userdb *UserDb) FindUserByEmail(email string) (*AuthUser, error) {
	var id int
	var uuid string
	var name string
	var username string
	var hashedPassword string
	var isVerified bool
	var canAuth bool

	err := userdb.findUserByEmailStmt.QueryRow(email).
		Scan(&id, &uuid, &name, &username, &hashedPassword, &isVerified, &canAuth)

	if err != nil {
		return nil, err //fmt.Errorf("there was an error with the database query")
	}

	authUser := NewAuthUser(id, uuid, name, username, email, hashedPassword, isVerified, canAuth)

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
	hash := HashPassword(password)

	_, err := userdb.setPasswordStmt.Exec(hash, userId)

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
	authUser, err := userdb.FindUserByEmail(email.Address)

	// try to create user if user does not exist
	if err != nil {
		// Create a uuid for the user id
		uuid := Uuid()

		hash := user.Hash()

		//log.Debug().Msgf("%s %s %s %s %s", user.Name, user.Email, hash, otp)

		_, err = userdb.createUserStmt.Exec(uuid, user.Name, email.Address, email.Address, hash)

		if err != nil {
			return nil, err
		}

		// Call function again to get the user details
		authUser, err = userdb.FindUserByEmail(email.Address)

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
