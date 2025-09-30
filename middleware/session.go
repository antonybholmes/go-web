package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/antonybholmes/go-web"
	"github.com/antonybholmes/go-web/auth"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

var (
	SessionOptsZero = sessions.Options{
		Path:     "/",
		MaxAge:   0,
		HttpOnly: true, //false,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	}

	SessionOptsClear = sessions.Options{
		Path:     "/",
		MaxAge:   -1,   // -1 to delete the cookie
		HttpOnly: true, //false,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	}
)

type SessionInfo struct {
	AuthUser  *auth.AuthUser `json:"user"`
	IsValid   bool           `json:"valid"`
	CreatedAt string         `json:"createdAt"`
	ExpiresAt string         `json:"expiresAt"`
	CsrfToken string         `json:"csrfToken"`
}

//var SESSION_OPT_24H *sessions.Options
//var SESSION_OPT_30_DAYS *sessions.Options
//var SESSION_OPT_7_DAYS *sessions.Options

func ReadSessionInfo(c *gin.Context, session sessions.Session) (*SessionInfo, error) {
	//sess := sessions.Default(c) //.Get(consts.SESSION_NAME, c)

	userData := session.Get(web.SessionUser)

	if userData == nil {
		return nil, fmt.Errorf("session user data is nil")
	}

	var user auth.AuthUser

	if err := json.Unmarshal([]byte(userData.(string)), &user); err != nil {
		return nil, err
	}

	//publicId, _ := sess.Values[SESSION_PUBLICID].(string)
	//roles, _ := sess.Values[SESSION_ROLES].(string)
	createdAt, _ := session.Get(web.SessionCreatedAt).(string)
	expires, _ := session.Get(web.SessionExpiresAt).(string)
	csrfToken, _ := session.Get(web.SessionCsrfToken).(string)

	//isValid := publicId != ""

	return &SessionInfo{AuthUser: &user,
			CreatedAt: createdAt,
			ExpiresAt: expires,
			CsrfToken: csrfToken},
		nil
}
