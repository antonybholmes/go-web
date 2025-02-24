package middleware

import (
	"encoding/json"
	"net/http"

	"github.com/antonybholmes/go-auth"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const (
	//SESSION_PUBLICID   string = "publicId"
	//SESSION_ROLES      string = "roles"
	SESSION_USER       string = "user"
	SESSION_CREATED_AT string = "createdAt"
	SESSION_EXPIRES_AT string = "expiresAt"
)

const (
	ERROR_CREATING_SESSION string = "error creating session"
)

var SESSION_OPT_ZERO sessions.Options

type SessionInfo struct {
	AuthUser  *auth.AuthUser `json:"user"`
	IsValid   bool           `json:"valid"`
	CreatedAt string         `json:"createdAt"`
	ExpiresAt string         `json:"expiresAt"`
}

//var SESSION_OPT_24H *sessions.Options
//var SESSION_OPT_30_DAYS *sessions.Options
//var SESSION_OPT_7_DAYS *sessions.Options

func init() {

	// HttpOnly and Secure are disabled so we can use them
	// cross domain for testing
	// http only false to allow js to delete etc on the client side

	// For sessions that should end when browser closes
	SESSION_OPT_ZERO = sessions.Options{
		Path:     "/",
		MaxAge:   0,
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	}

	// SESSION_OPT_24H = &sessions.Options{
	// 	Path:     "/",
	// 	MaxAge:   auth.MAX_AGE_DAY_SECS,
	// 	HttpOnly: false,
	// 	Secure:   true,
	// 	SameSite: http.SameSiteNoneMode,
	// }

	// SESSION_OPT_30_DAYS = &sessions.Options{
	// 	Path:     "/",
	// 	MaxAge:   auth.MAX_AGE_30_DAYS_SECS,
	// 	HttpOnly: false,
	// 	Secure:   true,
	// 	SameSite: http.SameSiteNoneMode,
	// }

	// SESSION_OPT_7_DAYS = &sessions.Options{
	// 	Path:     "/",
	// 	MaxAge:   auth.MAX_AGE_7_DAYS_SECS,
	// 	HttpOnly: false,
	// 	Secure:   true,
	// 	SameSite: http.SameSiteNoneMode,
	// }
}

func ReadSessionInfo(c *gin.Context) (*SessionInfo, error) {
	sess := sessions.Default(c) //.Get(consts.SESSION_NAME, c)

	userData, _ := sess.Get(SESSION_USER).(string)

	var user auth.AuthUser

	if err := json.Unmarshal([]byte(userData), &user); err != nil {
		return nil, err
	}

	//publicId, _ := sess.Values[SESSION_PUBLICID].(string)
	//roles, _ := sess.Values[SESSION_ROLES].(string)
	createdAt, _ := sess.Get(SESSION_CREATED_AT).(string)
	expires, _ := sess.Get(SESSION_EXPIRES_AT).(string)
	//isValid := publicId != ""

	return &SessionInfo{AuthUser: &user,
			CreatedAt: createdAt,
			ExpiresAt: expires},
		nil
}
