package auth

import "fmt"

// type PasswordlessLogin struct {
// 	Username string `json:"username" `
// 	UrlCallbackReq
// }

// type EmailPasswordLoginReq struct {
// 	Email    string `json:"email"`
// 	Password string `json:"password"`
// 	UrlCallbackReq
// }

// type UsernamePasswordLoginReq struct {
// 	Username string `json:"username"`
// 	Password string `json:"password"`
// 	UrlCallbackReq
// }

// type PasswordLoginReq struct {
// 	Password string `json:"password"`
// 	UrlCallbackReq
// }

// type PasswordResetReq struct {
// 	Password string `json:"password"`
// }

// type UsernameReq struct {
// 	Username string `json:"username"`
// }

type (
	NewPasswordReq struct {
		Password    string `json:"password"`
		NewPassword string `json:"newPassword"`
	}

	ApiKeyLoginReq struct {
		Key string `json:"key"`
	}

	// When user is logging in, they may supply some or
	// all of these as part of the authentication process
	// depending on the authentication methods enabled.
	// Authentication of the API endpoint is also considered
	// as part of this process so even if you supply these fields,
	// the method may ignore/not update them. Typically admin
	// privileges are required to user info though users can
	// update some of their own info such as name.
	UserBodyReq struct {
		RedirectUrlReq
		Id              string   `json:"id"`
		Username        string   `json:"username"`
		Email           string   `json:"email"`
		PictureUrl      string   `json:"pictureUrl"`
		Password        string   `json:"password"`
		NewPassword     string   `json:"newPassword"`
		OTP             string   `json:"otp"`
		Name            string   `json:"name"`
		ApiKey          string   `json:"apiKey"`
		Groups          []string `json:"groups"`
		EmailIsVerified bool     `json:"emailIsVerified"`
		StaySignedIn    bool     `json:"staySignedIn"`
	}

	SignupReq struct {
		RedirectUrlReq
		User
		Password string `json:"password"`
	}
)

func (user *SignupReq) String() string {
	return fmt.Sprintf("%s:%s:%s", user.FirstName, user.Email, user.Password)
}
