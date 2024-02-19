module github.com/antonybholmes/go-auth

go 1.22.0

replace github.com/antonybholmes/go-email => ../go-email

require (
	github.com/gofrs/uuid/v5 v5.0.0
	github.com/xyproto/randomstring v1.0.5
	golang.org/x/crypto v0.17.0
)
