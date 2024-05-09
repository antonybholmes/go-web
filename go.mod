module github.com/antonybholmes/go-auth

go 1.22.0

replace github.com/antonybholmes/go-mailer => ../go-mailer

replace github.com/antonybholmes/go-sys => ../go-sys

require (
	github.com/antonybholmes/go-sys v0.0.0-20240501232923-152b6e4cc204
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/google/uuid v1.6.0
	github.com/labstack/echo/v4 v4.12.0
	github.com/rs/zerolog v1.32.0
	github.com/xyproto/randomstring v1.0.5
	golang.org/x/crypto v0.23.0
)

require (
	github.com/labstack/gommon v0.4.2 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	golang.org/x/net v0.25.0 // indirect
	golang.org/x/sys v0.20.0 // indirect
	golang.org/x/text v0.15.0 // indirect
)
