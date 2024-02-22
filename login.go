package auth

type EmailOnlyLoginReq struct {
	Email string `json:"email" db:"email"`
	UrlCallbackReq
}

type EmailPasswordLoginReq struct {
	Email    string `json:"email" db:"email"`
	Password string `json:"password" db:"password"`
	UrlCallbackReq
}

type UsernamePasswordLoginReq struct {
	Username string `json:"email" db:"email"`
	Password string `json:"password" db:"password"`
	UrlCallbackReq
}

type PasswordLoginReq struct {
	Password string `json:"password" db:"password"`
	UrlCallbackReq
}

// type LoginUser struct {
// 	Email    string
// 	Password []byte
// }

// func NewLoginUser(email string, password string) *LoginUser {
// 	return &LoginUser{Email: email, Password: []byte(password)}
// }

// func LoginUserFromReq(req *LoginReq) *LoginUser {
// 	return NewLoginUser(req.Email, req.Password)
// }
