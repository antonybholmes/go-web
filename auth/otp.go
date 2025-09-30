package auth

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

// initialize once. Ideally would be a constant but Go doesn't
// support non primitive constants
var otp6Max *big.Int
var otp8Max *big.Int

// const KEY = "otp:"
const GLOBAL_OTP_MINUTE_RATE_KEY = "global:otp:minute"
const GLOBAL_OTP_HOUR_RATE_KEY = "global:otp:hour"
const GLOBAL_OTP_DAY_RATE_KEY = "global:otp:day"

type RateLimit struct {
	Limit     int64         // number of allowed attempts
	BlockTime time.Duration // block time duration
}

type GlobalRateLimit struct {
	Minute RateLimit // max attempts allowed across all email addresses
	Hour   RateLimit // max attempts allowed across all email addresses
	Day    RateLimit // max attempts allowed across all email addresses
}

type OTP struct {
	Context         context.Context
	RedisClient     *redis.Client
	ttl             time.Duration
	rateLimit       RateLimit       // max attempts allowed
	globalRateLimit GlobalRateLimit // max attempts allowed across all email addresses

}

func init() {
	// initialize once
	otp6Max = big.NewInt(1000000)
	otp8Max = big.NewInt(100000000)
}

func makeOTPKey(email string) string {
	return fmt.Sprintf("opt:email:%s:code", email)
}

func NewDefaultOTP(rdb *redis.Client) *OTP {
	return NewOTP(rdb, TTL_10_MINS,
		RateLimit{Limit: 5, BlockTime: TTL_5_MINS},
		GlobalRateLimit{
			Minute: RateLimit{Limit: 100, BlockTime: TTL_1_MIN},
			Hour:   RateLimit{Limit: 1000, BlockTime: TTL_HOUR},
			Day:    RateLimit{Limit: 10000, BlockTime: TTL_DAY},
		})
}

// NewOTP creates a new OTP manager with the given Redis client, TTL and rate limit settings. Global rate limit
// refers to the total number of OTPs that can be sent across all email addresses
func NewOTP(rdb *redis.Client, ttl time.Duration, rateLimit RateLimit, globalRateLimit GlobalRateLimit) *OTP {
	return &OTP{
		Context:         context.Background(),
		RedisClient:     rdb,
		ttl:             ttl,
		rateLimit:       rateLimit,
		globalRateLimit: globalRateLimit,
	}
}

// Returns the time to live duration for an OTP code
func (otp *OTP) TTL() time.Duration {
	return otp.ttl
}

func (otp *OTP) Cache8DigitOTP(email string) (string, bool, error) {

	code, err := Generate8DigitOTP() //Generate6DigitCode()

	if err != nil {
		return "", false, err
	}

	return otp.cacheOTP(email, code)
}

// CacheOTP creates and caches a 6 digit OTP code in Valkey/Redis for the given email address.
// It also enforces rate limiting.
func (otp *OTP) Cache6DigitOTP(email string) (string, bool, error) {

	code, err := Generate6DigitOTP() //Generate6DigitCode()

	if err != nil {
		return "", false, err
	}

	return otp.cacheOTP(email, code)
}

// CacheOTP creates and caches an OTP code in Valkey/Redis for the given email address.
// It also enforces rate limiting.
func (otp *OTP) cacheOTP(email string, code string) (string, bool, error) {
	exceeded, err := otp.GlobalRateLimitForOTPCachingExceeded()

	if err != nil {
		return "", exceeded, err
	}

	exceeded, err = otp.RateLimitForOTPCachingExceeded(email)

	if err != nil {
		return "", exceeded, err
	}

	err = otp.storeOTP(email, code)

	if err != nil {
		return "", false, err
	}

	return code, false, nil
}

func (otp *OTP) deleteOTP(email string) error {
	key := makeOTPKey(email)
	return otp.RedisClient.Del(otp.Context, key).Err()
}

func (otp *OTP) getOTP(email string) (string, error) {
	key := makeOTPKey(email)
	return otp.RedisClient.Get(otp.Context, key).Result()
}

func (otp *OTP) storeOTP(email string, code string) error {
	key := makeOTPKey(email)
	return otp.RedisClient.Set(otp.Context, key, code, otp.ttl).Err() // expires in 5 mins
}

func (otp *OTP) ValidateOTP(email string, input string) (bool, error) {
	// distinguish between an error with redis and when
	// rate is exceeded
	exceeded, err := otp.RateLimitForOTPValidationExceeded(email)

	if err != nil {
		return false, err
	}

	if exceeded {
		return false, fmt.Errorf("too many validation attempts")
	}

	stored, err := otp.getOTP(email)

	log.Debug().Msgf("validating %s %s %s", email, input, stored)

	if err == redis.Nil {
		return false, nil // not found or expired
	} else if err != nil {
		return false, err
	}

	if stored != input {
		return false, nil
	}

	// Remove after use
	err = otp.deleteOTP(email)

	if err != nil {
		return false, err
	}

	return true, nil
}

// Limits the number of OTPs that can be sent by the system across all email addresses
// Returns true if rate limit exceeded along with an error.
// Returns false and an error if there was an error connecting to Redis.
// Returns false, nil if rate limit not exceeded.
func (otp *OTP) GlobalRateLimitForOTPCachingExceeded() (bool, error) {

	attempts, err := otp.RedisClient.Incr(otp.Context, GLOBAL_OTP_MINUTE_RATE_KEY).Result()

	if err != nil {
		return false, err
	}

	if attempts == 1 {
		// on first attempt set expiry
		otp.RedisClient.Expire(otp.Context, GLOBAL_OTP_MINUTE_RATE_KEY, otp.globalRateLimit.Minute.BlockTime)
	}

	if attempts > otp.globalRateLimit.Minute.Limit {
		return true, fmt.Errorf("the global per minute rate limit for code generation has been exceeded")
	}

	attempts, err = otp.RedisClient.Incr(otp.Context, GLOBAL_OTP_HOUR_RATE_KEY).Result()

	if err != nil {
		return false, err
	}

	if attempts == 1 {
		// on first attempt set expiry
		otp.RedisClient.Expire(otp.Context, GLOBAL_OTP_HOUR_RATE_KEY, otp.globalRateLimit.Hour.BlockTime)
	}

	if attempts > otp.globalRateLimit.Hour.Limit {
		return true, fmt.Errorf("the global hourly rate limit for code generation has been exceeded")
	}

	attempts, err = otp.RedisClient.Incr(otp.Context, GLOBAL_OTP_DAY_RATE_KEY).Result()

	if err != nil {
		return false, err
	}

	if attempts == 1 {
		// on first attempt set expiry
		otp.RedisClient.Expire(otp.Context, GLOBAL_OTP_DAY_RATE_KEY, otp.globalRateLimit.Day.BlockTime)
	}

	if attempts > otp.globalRateLimit.Day.Limit {
		return true, fmt.Errorf("the global daily rate limit for code generation has been exceeded")
	}

	return false, nil
}

// limits the number of OTPs that can be sent to an email address
func (otp *OTP) RateLimitForOTPCachingExceeded(email string) (bool, error) {
	key := fmt.Sprintf("otp:email:%s:send:attempts", email)

	attempts, err := otp.RedisClient.Incr(otp.Context, key).Result()

	if err != nil {
		return false, err
	}

	if attempts == 1 {
		// on first attempt set expiry
		otp.RedisClient.Expire(otp.Context, key, otp.rateLimit.BlockTime)
	}

	if attempts > otp.rateLimit.Limit {
		return true, fmt.Errorf("there have been too many attempts to create a code for this email address, please try again later")
	}

	return false, nil
}

// Returns true if rate limit exceeded
func (otp *OTP) RateLimitForOTPValidationExceeded(email string) (bool, error) {
	key := fmt.Sprintf("otp:email:%s:check:attempts", email)

	attempts, err := otp.RedisClient.Incr(otp.Context, key).Result()

	if err != nil {
		return false, err
	}

	if attempts == 1 {
		// on first attempt set expiry
		otp.RedisClient.Expire(otp.Context, key, otp.rateLimit.BlockTime)
	}

	return attempts > otp.rateLimit.Limit, nil
}

func Generate6DigitOTP() (string, error) {
	//max := big.NewInt(1000000) // 6 digits: 000000 - 999999

	n, err := rand.Int(rand.Reader, otp6Max)

	if err != nil {
		return "", err
	}

	// "%06d" padds with leading zeros if necessary
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func Generate8DigitOTP() (string, error) {
	//max := big.NewInt(1000000) // 6 digits: 000000 - 999999

	n, err := rand.Int(rand.Reader, otp8Max)

	if err != nil {
		return "", err
	}

	// "%08d" padds with leading zeros if necessary
	return fmt.Sprintf("%08d", n.Int64()), nil
}
