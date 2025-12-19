package middleware

import (
	"errors"
	"net/mail"

	"github.com/antonybholmes/go-sys/log"
	"github.com/antonybholmes/go-web"

	"github.com/antonybholmes/go-web/auth"
	"github.com/antonybholmes/go-web/auth/userdb"
	userdbcache "github.com/antonybholmes/go-web/auth/userdb/cache"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

//
// Standardized data checkers for checking header and body contain
// the correct data for a route
//

type Validator struct {
	c           *gin.Context
	Address     *mail.Address
	UserBodyReq *auth.UserBodyReq

	AuthUser *auth.AuthUser
	Claims   *auth.AuthUserJwtClaims
	Err      error
}

func NewValidator(c *gin.Context) *Validator {
	return &Validator{
		c:           c,
		Address:     nil,
		UserBodyReq: nil,
		AuthUser:    nil,
		Claims:      nil,
		Err:         nil}

}

// Returns the validator if no errors have been encountered so far
// otherwise returns an error
func (validator *Validator) Ok() (*Validator, error) {
	if validator.Err != nil {
		return nil, validator.Err
	} else {
		return validator, nil
	}
}

// If the validator does not encounter errors, it will run the success function
// allowing you to extract data from the validator, otherwise it returns an error
// without running the function
func (validator *Validator) Success(success func(validator *Validator)) {

	if validator.Err != nil {
		validator.c.Error(validator.Err)
		return
	}

	success(validator)
}

func (validator *Validator) ParseSignInRequestBody() *Validator {
	if validator.Err != nil {
		return validator
	}

	if validator.UserBodyReq == nil {
		var req auth.UserBodyReq

		err := validator.c.ShouldBindJSON(&req)

		if err != nil {
			validator.Err = err
		} else {
			validator.UserBodyReq = &req
		}
	}

	return validator
}

func (validator *Validator) CheckUsernameIsWellFormed() *Validator {
	validator.ParseSignInRequestBody()

	if validator.Err != nil {
		return validator
	}

	//log.Debug().Msgf("check username well formed %s", validator.SignInBodyReq.Username)

	err := userdb.CheckUsername(validator.UserBodyReq.Username)

	if err != nil {
		log.Debug().Msgf("check user name err %s", err)
		validator.Err = err
	}

	return validator
}

func (validator *Validator) CheckEmailIsWellFormed() *Validator {

	validator.ParseSignInRequestBody()

	if validator.Err != nil {
		return validator
	}

	//address, err := CheckEmailIsWellFormed(validator.Req.Email)

	address, err := mail.ParseAddress(validator.UserBodyReq.Email)

	if err != nil {
		validator.Err = err
	} else {
		validator.Address = address
	}

	return validator
}

func (validator *Validator) LoadAuthUserFromId() *Validator {

	if validator.Err != nil {
		return validator
	}

	authUser, err := userdbcache.FindUserById(validator.UserBodyReq.Id)

	if err != nil {
		validator.Err = auth.ErrUserDoesNotExist
	} else {
		validator.AuthUser = authUser
	}

	return validator

}

func (validator *Validator) LoadAuthUserFromEmail() *Validator {
	validator.CheckEmailIsWellFormed()

	if validator.Err != nil {
		return validator
	}

	authUser, err := userdbcache.FindUserByEmail(validator.Address)

	if err != nil {
		validator.Err = auth.ErrUserDoesNotExist
	} else {
		validator.AuthUser = authUser
	}

	return validator

}

func (validator *Validator) LoadAuthUserFromUsername() *Validator {
	validator.ParseSignInRequestBody()

	if validator.Err != nil {
		return validator
	}

	authUser, err := userdbcache.FindUserByUsername(validator.UserBodyReq.Username)

	//log.Debug().Msgf("beep2 %s", authUser.Username)

	if err != nil {
		validator.Err = auth.ErrUserDoesNotExist
	} else {
		validator.AuthUser = authUser
	}

	return validator

}

func (validator *Validator) LoadAuthUserFromSession() *Validator {
	validator.ParseSignInRequestBody()

	if validator.Err != nil {
		return validator
	}

	session := sessions.Default(validator.c)

	sessionData, err := ReadSessionInfo(validator.c, session)

	if err != nil {
		validator.Err = errors.New("user not in session")
		validator.CheckIsValidRefreshToken().CheckUsernameIsWellFormed()
	}

	validator.AuthUser = sessionData.AuthUser

	return validator
}

func (validator *Validator) CheckAuthUserIsLoaded() *Validator {
	if validator.Err != nil {
		return validator
	}

	if validator.AuthUser == nil {
		validator.Err = auth.NewAccountError("no auth user")
	}

	return validator
}

func (validator *Validator) CheckUserHasVerifiedEmailAddress() *Validator {
	validator.CheckAuthUserIsLoaded()

	if validator.Err != nil {
		return validator
	}

	if validator.AuthUser.EmailVerifiedAt == nil {
		validator.Err = auth.NewAccountError("email address not verified")
	}

	return validator
}

// If using jwt middleware, token is put into user variable
// and we can extract data from the jwt
func (validator *Validator) LoadTokenClaims() *Validator {
	if validator.Err != nil {
		return validator
	}

	if validator.Claims == nil {
		user, ok := validator.c.Get(web.SessionUser)

		if ok {
			validator.Claims = user.(*auth.AuthUserJwtClaims)
		}
	}

	return validator
}

// Extracts public id from token, checks user exists and calls success function.
// If claims argument is nil, function will search for claims automatically.
// If claims are supplied, this step is skipped. This is so this function can
// be nested in other call backs that may have already extracted the claims
// without having to repeat this part.
func (validator *Validator) LoadAuthUserFromToken() *Validator {
	validator.LoadTokenClaims()

	if validator.Err != nil {
		return validator
	}

	authUser, err := userdbcache.FindUserById(validator.Claims.UserId)

	if err != nil {
		validator.Err = auth.ErrUserDoesNotExist
	} else {
		validator.AuthUser = authUser
	}

	return validator
}

func (validator *Validator) CheckIsValidRefreshToken() *Validator {
	validator.LoadTokenClaims()

	if validator.Err != nil {
		return validator
	}

	if validator.Claims.Type != auth.TokenTypeRefresh {
		validator.Err = auth.NewTokenError("no refresh token")
	}

	return validator

}

func (validator *Validator) CheckIsValidAccessToken() *Validator {
	validator.LoadTokenClaims()

	if validator.Err != nil {
		return validator
	}

	if validator.Claims.Type != auth.TokenTypeAccess {
		validator.Err = auth.NewTokenError("no access token")
	}

	return validator
}

// func ParseSignInRequestBody(c *gin.Context) (*UserBodyReq, error) {

// 	var req UserBodyReq

// 	err := c.ShouldBindJSON(&req)

// 	if err != nil {
// 		return nil, err
// 	}

// 	return &req, nil

// }
