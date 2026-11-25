package middleware

import (
	"errors"
	"net/mail"
	"strconv"

	"github.com/antonybholmes/go-sys/log"
	"github.com/antonybholmes/go-web"

	"github.com/antonybholmes/go-web/auth"
	"github.com/antonybholmes/go-web/auth/token"
	"github.com/antonybholmes/go-web/auth/userdb"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

//
// Standardized data checkers for checking header and body contain
// the correct data for a route
//

type Validator struct {
	UserDB      userdb.UserDB
	Err         error
	c           *gin.Context
	Address     *mail.Address
	UserBodyReq *auth.UserBodyReq
	AuthUser    *auth.AuthUser
	Claims      *token.AuthUserJwtClaims
	Page        int
	PageSize    int
}

func NewValidator(c *gin.Context, userDB userdb.UserDB) *Validator {
	return &Validator{
		c:           c,
		UserDB:      userDB,
		Address:     nil,
		UserBodyReq: nil,
		AuthUser:    nil,
		Claims:      nil,
		Page:        1,
		PageSize:    100,
		Err:         nil}

}

// Returns the validator if no errors have been encountered so far
// otherwise returns an error
func (v *Validator) Ok() (*Validator, error) {
	if v.Err != nil {
		return nil, v.Err
	} else {
		return v, nil
	}
}

// If the validator does not encounter errors, it will run the success function
// allowing you to extract data from the validator, otherwise it returns an error
// without running the function
func (v *Validator) Success(success func(validator *Validator)) {

	if v.Err != nil {
		v.c.Error(v.Err)
		return
	}

	success(v)
}

func (v *Validator) ParseSignInRequestBody() *Validator {
	if v.Err != nil {
		return v
	}

	if v.UserBodyReq == nil {
		var req auth.UserBodyReq

		err := v.c.ShouldBindJSON(&req)

		if err != nil {
			v.Err = err
		} else {
			v.UserBodyReq = &req
		}
	}

	return v
}

func (v *Validator) CheckUsernameIsWellFormed() *Validator {
	v.ParseSignInRequestBody()

	if v.Err != nil {
		return v
	}

	//log.Debug().Msgf("check username well formed %s", validator.SignInBodyReq.Username)

	err := userdb.CheckUsername(v.UserBodyReq.Username)

	if err != nil {
		log.Debug().Msgf("check user name err %s", err)
		v.Err = err
	}

	return v
}

func (v *Validator) CheckEmailIsWellFormed() *Validator {

	v.ParseSignInRequestBody()

	if v.Err != nil {
		return v
	}

	//address, err := CheckEmailIsWellFormed(validator.Req.Email)

	address, err := mail.ParseAddress(v.UserBodyReq.Email)

	if err != nil {
		v.Err = err
	} else {
		v.Address = address
	}

	return v
}

func (v *Validator) LoadAuthUserFromId() *Validator {

	if v.Err != nil {
		return v
	}

	authUser, err := v.UserDB.FindUserById(v.UserBodyReq.Id)

	if err != nil {
		v.Err = auth.ErrUserDoesNotExist
	} else {
		v.AuthUser = authUser
	}

	return v

}

func (v *Validator) LoadAuthUserFromEmail() *Validator {
	v.CheckEmailIsWellFormed()

	if v.Err != nil {
		return v
	}

	authUser, err := v.UserDB.FindUserByEmail(v.Address)

	if err != nil {
		v.Err = auth.ErrUserDoesNotExist
	} else {
		v.AuthUser = authUser
	}

	return v

}

func (v *Validator) LoadAuthUserFromUsername() *Validator {
	v.ParseSignInRequestBody()

	if v.Err != nil {
		return v
	}

	authUser, err := v.UserDB.FindUserByUsername(v.UserBodyReq.Username)

	//log.Debug().Msgf("beep2 %s", authUser.Username)

	if err != nil {
		v.Err = auth.ErrUserDoesNotExist
	} else {
		v.AuthUser = authUser
	}

	return v

}

func (v *Validator) LoadAuthUserFromSession() *Validator {
	v.ParseSignInRequestBody()

	if v.Err != nil {
		return v
	}

	session := sessions.Default(v.c)

	sessionData, err := ReadSessionInfo(v.c, session)

	if err != nil {
		v.Err = errors.New("user not in session")
		v.CheckIsValidRefreshToken().CheckUsernameIsWellFormed()
	}

	v.AuthUser = sessionData.AuthUser

	return v
}

func (v *Validator) CheckAuthUserIsLoaded() *Validator {
	if v.Err != nil {
		return v
	}

	if v.AuthUser == nil {
		v.Err = auth.NewAccountError("no auth user")
	}

	return v
}

func (v *Validator) CheckUserHasVerifiedEmailAddress() *Validator {
	v.CheckAuthUserIsLoaded()

	if v.Err != nil {
		return v
	}

	if v.AuthUser.EmailVerifiedAt == nil {
		v.Err = auth.NewAccountError("email address not verified")
	}

	return v
}

// If using jwt middleware, token is put into user variable
// and we can extract data from the jwt
func (v *Validator) LoadTokenClaims() *Validator {
	if v.Err != nil {
		return v
	}

	if v.Claims == nil {
		user, ok := v.c.Get(web.SessionUser)

		if ok {
			v.Claims = user.(*token.AuthUserJwtClaims)
		}
	}

	return v
}

// Extracts public id from token, checks user exists and calls success function.
// If claims argument is nil, function will search for claims automatically.
// If claims are supplied, this step is skipped. This is so this function can
// be nested in other call backs that may have already extracted the claims
// without having to repeat this part.
func (v *Validator) LoadAuthUserFromToken() *Validator {
	v.LoadTokenClaims()

	if v.Err != nil {
		return v
	}

	authUser, err := v.UserDB.FindUserById(v.Claims.Subject)

	if err != nil {
		v.Err = auth.ErrUserDoesNotExist
	} else {
		v.AuthUser = authUser
	}

	return v
}

func (v *Validator) CheckIsValidRefreshToken() *Validator {
	v.LoadTokenClaims()

	if v.Err != nil {
		return v
	}

	if v.Claims.Type != token.TokenTypeRefresh {
		v.Err = token.NewTokenError("no refresh token")
	}

	return v

}

func (v *Validator) CheckIsValidAccessToken() *Validator {
	v.LoadTokenClaims()

	if v.Err != nil {
		return v
	}

	if v.Claims.Type != token.TokenTypeAccess {
		v.Err = token.NewTokenError("no access token")
	}

	return v
}

// ParsePaging parses the page and pageSize query parameters, defaulting to 1 and 10.
func (v *Validator) ParsePaging() *Validator {
	if v.Err != nil {
		return v
	}

	page := v.c.DefaultQuery("page", "1")
	pageNum, err := strconv.Atoi(page)

	if err != nil {
		v.Err = err
		return v
	}

	pageSize := v.c.DefaultQuery("pageSize", "100")
	pageSizeNum, err := strconv.Atoi(pageSize)

	if err != nil {
		v.Err = err
		return v
	}

	v.Page = pageNum
	v.PageSize = pageSizeNum

	return v
}

// func ParseSignInRequestBody(c *gin.Context) (*UserBodyReq, error) {

// 	var req UserBodyReq

// 	err := c.ShouldBindJSON(&req)

// 	if err != nil {
// 		return nil, err
// 	}

// 	return &req, nil

// }
