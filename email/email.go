package email

import (
	"github.com/antonybholmes/go-auth"
)

var emailer = auth.NewSMTPEmail()

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

func SendEmail(to string, message string) {
	emailer.SendEmail(to, message)
}

func Compose(to string, subject string, body string) error {
	return emailer.Compose(to, subject, body)
}
