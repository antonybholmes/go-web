module github.com/antonybholmes/go-auth

go 1.22.0

replace github.com/antonybholmes/go-env => ../go-env

require (
	github.com/gofrs/uuid/v5 v5.0.0
	github.com/rs/zerolog v1.32.0
	github.com/xyproto/randomstring v1.0.5
	golang.org/x/crypto v0.17.0
)

require (
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	golang.org/x/sys v0.15.0 // indirect
)
