package tokengen

import (
	"sync"

	"github.com/antonybholmes/go-web/auth/token"
)

var (
	tc   *token.TokenCreator
	once sync.Once
)

func Init(tokenSigner token.TokenSigner) {
	once.Do(func() {
		tc = token.NewTokenCreator(tokenSigner)
	})
}

func Instance() *token.TokenCreator {
	return tc
}
