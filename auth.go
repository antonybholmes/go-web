package auth

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/gofrs/uuid/v5"
	"golang.org/x/crypto/bcrypt"
)

// See https://echo.labstack.com/docs/cookbook/jwt#login

// partially based on https://betterprogramming.pub/hands-on-with-jwt-in-golang-8c986d1bb4c0

const JWT_TOKEN_EXPIRES_HOURS time.Duration = 24
const INVALID_JWT_MESSAGE string = "Invalid JWT"
const FIND_USER_BY_EMAIL_SQL string = `SELECT id, user_id, password FROM users WHERE users.email = ?`
const CREATE_USER_SQL = `INSERT INTO users (user_id, email, password) VALUES(?, ?, ?)`

type User struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type LoginUser struct {
	User
	Password []byte `json:"password"`
}

func NewLoginUser(email string, password string) *LoginUser {
	return &LoginUser{User: User{Email: email}, Password: []byte(password)}
}

func (user *LoginUser) HashPassword() ([]byte, error) {
	bytes, err := bcrypt.GenerateFromPassword(user.Password, bcrypt.DefaultCost)

	if err != nil {
		return nil, err
	}

	return bytes, nil
}

type AuthUser struct {
	User
	Id             int    `json:"int"`
	UserId         string `json:"user_id"`
	HashedPassword []byte `json:"hashed_password"`
}

func NewAuthUser(id int, userId string, hashedPassword string, user *LoginUser) *AuthUser {
	return &AuthUser{User: User{Name: user.Name, Email: user.Email}, Id: id, UserId: userId, HashedPassword: []byte(hashedPassword)}
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
	createUserStmt      *sql.Stmt
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

	createUserStmt, err := db.Prepare(CREATE_USER_SQL)

	if err != nil {
		return nil, err
	}

	return &UserDb{db, findUserByEmailStmt, createUserStmt}, nil
}

func (userdb *UserDb) Close() {
	userdb.db.Close()
}

func (userdb *UserDb) FindUserByEmail(user *LoginUser) (*AuthUser, error) {
	var id int
	var userId string
	var hashedPassword string

	err := userdb.findUserByEmailStmt.QueryRow(user.Email).Scan(&id, &userId, &hashedPassword)

	if err != nil {
		return nil, err //fmt.Errorf("there was an error with the database query")
	}

	authUser := NewAuthUser(id, userId, hashedPassword, user)

	//log.Printf("find %s %t\n", user.Email, authUser.CheckPasswords(user.Password))

	// check password hash matches hash in database

	return authUser, nil
}

func (userdb *UserDb) CreateUser(user *LoginUser) (*AuthUser, error) {

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

	hash, err := user.HashPassword()

	if err != nil {
		return nil, err
	}

	_, err = userdb.createUserStmt.Exec(u1, user.Email, hash)

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
