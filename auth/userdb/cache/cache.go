package cache

import (
	"sync"

	"github.com/antonybholmes/go-web/auth/userdb"
	"github.com/antonybholmes/go-web/auth/userdb/postgres"
)

// pretend its a global const
var (
	instance userdb.UserDB
	once     sync.Once
)

func Instance() userdb.UserDB {
	once.Do(func() {
		instance = postgres.NewPostgresUserDB()
	})
	return instance
}
