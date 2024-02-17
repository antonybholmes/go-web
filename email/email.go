package email

import (
	"os"

	"github.com/antonybholmes/go-auth"
	"github.com/antonybholmes/go-env"
)

var emailer = auth.NewSMTPEmailer()

func init() {
	// force loading of enviromental variables if not done so
	env.Load()

	// Attempt to initialize by scanning enviromental variables.
	// If user has set them, magic, otherwise user will have to manually
	// specify
	emailer.SetName(os.Getenv("NAME")).
		SetUser(env.GetStr("SMTP_USER", ""), env.GetStr("SMTP_PASSWORD", "")).
		SetHost(env.GetStr("SMTP_HOST", ""), env.GetUint32("SMTP_PORT", 587)).
		SetFrom(env.GetStr("SMTP_FROM", ""))
}

func SetName(name string) *auth.SMTPEmailer {
	return emailer.SetName(name)
}

func SetUser(user string, password string) *auth.SMTPEmailer {
	return emailer.SetUser(user, password)
}

func SetHost(host string, port uint) *auth.SMTPEmailer {
	return emailer.SetHost(host, port)
}

func From() string {
	return emailer.From()
}

func SetFrom(from string) *auth.SMTPEmailer {
	return emailer.SetFrom(from)
}

func SendEmail(to string, body []byte) error {
	return emailer.SendEmail(to, body)
}

func Compose(to string, subject string, body string) error {
	return emailer.Compose(to, subject, body)
}
