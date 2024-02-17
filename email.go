package auth

import (
	"fmt"
	"net/smtp"

	"github.com/rs/zerolog/log"
)

type ISMTPEmailer interface {
	SetName(name string) *SMTPEmailer

	SetUser(user string, password string) *SMTPEmailer

	SetHost(host string, port uint) *SMTPEmailer

	From() string

	SetFrom(from string) *SMTPEmailer

	SendEmail(to string, message string) error

	Compose(to string, subject string, body string) error
}

type SMTPEmailer struct {
	name     string
	user     string
	password string
	host     string
	port     uint
	addr     string
	from     string
}

func NewSMTPEmailer() *SMTPEmailer {
	host := ""
	port := uint(587)
	addr := fmt.Sprintf("%s:%d", host, port)

	return &SMTPEmailer{
		name:     "",
		user:     "",
		password: "",
		host:     host,
		port:     port,
		addr:     addr,
		from:     ""}
}

func (emailer *SMTPEmailer) SetName(name string) *SMTPEmailer {
	emailer.name = name
	return emailer
}

func (emailer *SMTPEmailer) SetUser(user string, password string) *SMTPEmailer {
	emailer.user = user
	emailer.password = password
	return emailer
}

func (emailer *SMTPEmailer) SetHost(host string, port uint) *SMTPEmailer {
	emailer.host = host
	emailer.port = port
	emailer.addr = fmt.Sprintf("%s:%d", emailer.host, emailer.port)
	return emailer
}

func (emailer *SMTPEmailer) From() string {
	return emailer.from
}

func (emailer *SMTPEmailer) SetFrom(from string) *SMTPEmailer {
	emailer.from = from
	return emailer
}

func (emailer *SMTPEmailer) SendEmail(to string, body []byte) error {

	//from := os.Getenv("EMAIL")

	//password := os.Getenv("SMTP_PASSWORD")
	//user := os.Getenv("SMTP_USER")

	// Receiver email address.
	//to := "antony@antonyholmes.dev"

	// smtp server configuration.
	//smtpHost := os.Getenv("SMTP_HOST")
	//smtpPort := os.Getenv("SMTP_PORT")

	//addr := fmt.Sprintf("%s:%s", smtpHost, os.Getenv("SMTP_PORT"))

	//code := randomstring.CookieFriendlyString(32)

	// Message.
	// message := []byte(fmt.Sprintf("From: Experiment Database Service <%s>\r\n", emailer.from) +
	// 	fmt.Sprintf("To: %s\r\n", to) +
	// 	fmt.Sprintf("Subject: %s OTP code\r\n", os.Getenv("NAME")) +
	// 	"\r\n" +
	// 	fmt.Sprintf("Your one time code is: %s\r\n", code))

	// Authentication.
	auth := smtp.PlainAuth("", emailer.user, emailer.password, emailer.host)

	// Sending email.
	err := smtp.SendMail(emailer.addr, auth, emailer.from, []string{
		to,
	}, body)

	if err != nil {
		log.Error().Msgf("%s", err)
		return err
	}

	log.Error().Msgf("Email Sent Successfully!")

	return nil
}

func (emailer *SMTPEmailer) Compose(to string, subject string, body string) error {
	message := fmt.Sprintf("From: %s <%s>\r\n", emailer.name, emailer.from) +
		fmt.Sprintf("To: %s\r\n", to) +
		fmt.Sprintf("Subject: %s \r\n", subject) +
		"\r\n" +
		fmt.Sprintf("%s\r\n", body)

	log.Debug().Msg(message)

	return emailer.SendEmail(to, []byte(message))
}
