package auth

type PasswordlessLoginReq struct {
	Email string `json:"email"`
	UrlCallbackReq
}

type LoginReq struct {
	PasswordlessLoginReq
	Password string `json:"password"`
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
