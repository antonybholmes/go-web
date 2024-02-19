package auth

type LoginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	UrlCallbackReq
}

type LoginUser struct {
	Email    string `json:"email"`
	Password []byte `json:"password"`
}

func NewLoginUser(email string, password string) *LoginUser {
	return &LoginUser{Email: email, Password: []byte(password)}
}

func LoginUserFromReq(req *LoginReq) *LoginUser {
	return NewLoginUser(req.Email, req.Password)
}
