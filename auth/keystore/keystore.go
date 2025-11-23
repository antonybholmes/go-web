package keystore

import (
	"crypto/ed25519"
	"sync"
	"time"

	userdb "github.com/antonybholmes/go-web/auth/userdb/cache"
)

type (
	PublicKeyCacheItem struct {
		Keys      []ed25519.PublicKey
		ExpiresAt time.Time
	}

	PublicKeyCache struct {
		mu    sync.RWMutex
		items map[string]PublicKeyCacheItem // userID -> keys
		ttl   time.Duration
	}
)

const DefaultTTL = 10 * time.Minute

var instance = &PublicKeyCache{
	items: make(map[string]PublicKeyCacheItem),
	ttl:   DefaultTTL,
}

func (c *PublicKeyCache) SetTTL(d time.Duration) {
	c.mu.Lock()
	c.ttl = d
	c.mu.Unlock()
}

// GetUserKeys retrieves the public keys for a user from the cache.
// Returns the keys and true if found and not expired, else nil and false.
func (c *PublicKeyCache) GetUserKeys(userID string) ([]ed25519.PublicKey, bool) {
	c.mu.RLock()
	item, found := c.items[userID]
	c.mu.RUnlock()

	if !found || time.Now().After(item.ExpiresAt) {
		return nil, false
	}

	return item.Keys, true
}

func (c *PublicKeyCache) GetUserPublicKeysCached(userID string) ([]ed25519.PublicKey, error) {
	if keys, ok := c.GetUserKeys(userID); ok {
		return keys, nil
	}

	// fallback to DB
	user, err := userdb.FindUserById(userID)

	if err != nil {
		return nil, err
	}

	keys, err := userdb.UserPublicKeys(user)

	if err != nil {
		return nil, err
	}

	c.SetUserKeys(userID, keys)

	return keys, nil
}

// SetUserKeys sets the public keys for a user in the cache.
func (c *PublicKeyCache) SetUserKeys(userID string, keys []ed25519.PublicKey) {
	c.mu.Lock()
	c.items[userID] = PublicKeyCacheItem{
		Keys:      keys,
		ExpiresAt: time.Now().Add(c.ttl), // reasonable TTL
	}
	c.mu.Unlock()
}

// Cleanup removes expired entries. Call periodically in background
func (c *PublicKeyCache) Cleanup() {
	now := time.Now()
	c.mu.Lock()
	for userID, item := range c.items {
		if now.After(item.ExpiresAt) {
			delete(c.items, userID)
		}
	}
	c.mu.Unlock()
}

// StartCleanupTicker starts a goroutine that periodically calls Cleanup at the specified interval
// pkcache.Cache.StartCleanupTicker(5*time.Minute, stop)
// to stop, close the stop channel
// e.g., close(stop)
// Example usage:
//
//	stop := make(chan struct{})
//	pkcache.StartCleanupTicker(5*time.Minute, stop)
//	// To stop the ticker later:
//	// close(stop)
func (c *PublicKeyCache) StartCleanupTicker(interval time.Duration, stopCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			// in this select, we wait for either the ticker or the stop channel
			// unlike sequential select statements, selects with channels will
			// listen for all cases simultaneously
			select {
			case <-ticker.C:
				c.Cleanup()
			case <-stopCh:
				return
			}
		}
	}()
}

func Instance() *PublicKeyCache {
	return instance
}

func SetCacheTTL(d time.Duration) {
	instance.SetTTL(d)
}

func GetUserPublicKeysCached(userID string) ([]ed25519.PublicKey, error) {
	return instance.GetUserPublicKeysCached(userID)
}

// func GetUserKeys(userID string) ([]ed25519.PublicKey, bool) {
// 	return instance.GetUserKeys(userID)
// }

func SetUserKeys(userID string, keys []ed25519.PublicKey) {
	instance.SetUserKeys(userID, keys)
}

func StartCleanupTicker(interval time.Duration, stopCh <-chan struct{}) {
	instance.StartCleanupTicker(interval, stopCh)
}
