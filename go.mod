module github.com/antonybholmes/go-auth

go 1.22.0

replace github.com/antonybholmes/go-mailer => ../go-mailer

replace github.com/antonybholmes/go-sys => ../go-sys

require (
	github.com/antonybholmes/go-sys v0.0.0-20240219230548-9ab0febd5fc5
	github.com/golang-jwt/jwt/v5 v5.2.0
	github.com/google/uuid v1.6.0
	github.com/xyproto/randomstring v1.0.5
	golang.org/x/crypto v0.19.0
)
