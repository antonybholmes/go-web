package auth

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/antonybholmes/go-web"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

const (
	GlobalOtpMinuteRateKey = "global:otp:minute"
	GlobalOtpHourRateKey   = "global:otp:hour"
	GlobalOtpDayRateKey    = "global:otp:day"
)

// initialize once. Ideally would be a constant but Go doesn't
// support non primitive constants
var (
	Otp6MaxNum *big.Int = big.NewInt(1000000)
	Otp8MaxNum *big.Int = big.NewInt(100000000)
)

type RateLimitError struct {
	Message string
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("rate limit error: %s", e.Message)
}

func NewRateLimitError(message string) *RateLimitError {
	return &RateLimitError{Message: message}
}

func IsRateLimitError(err error) bool {
	_, ok := err.(*RateLimitError)
	return ok
}

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

func makeOTPKey(email string) string {
	return fmt.Sprintf("opt:email:%s:code", email)
}

func NewDefaultOTP(rdb *redis.Client) *OTP {
	return NewOTP(rdb, Ttl10Mins,
		RateLimit{Limit: 5, BlockTime: Ttl5Mins},
		GlobalRateLimit{
			Minute: RateLimit{Limit: 100, BlockTime: Ttl1Min},
			Hour:   RateLimit{Limit: 1000, BlockTime: TtlHour},
			Day:    RateLimit{Limit: 10000, BlockTime: TtlDay},
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

func (otp *OTP) Cache8DigitOTP(email string) (string, error) {

	code, err := Generate8DigitOTP() //Generate6DigitCode()

	if err != nil {
		return "", err
	}

	return otp.cacheOTP(email, code)
}

// CacheOTP creates and caches a 6 digit OTP code in Valkey/Redis for the given email address.
// It also enforces rate limiting.
func (otp *OTP) Cache6DigitOTP(email string) (string, error) {

	code, err := Generate6DigitOTP() //Generate6DigitCode()

	if err != nil {
		return "", err
	}

	return otp.cacheOTP(email, code)
}

// CacheOTP creates and caches an OTP code in Valkey/Redis for the given email address.
// It also enforces rate limiting.
func (otp *OTP) cacheOTP(email string, code string) (string, error) {
	err := otp.GlobalRateLimitForOTPCachingExceeded()

	if err != nil {
		return "", err
	}

	err = otp.RateLimitForOTPCachingExceeded(email)

	if err != nil {
		return "", err
	}

	err = otp.storeOTP(email, code)

	if err != nil {
		return "", err
	}

	return code, nil
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

func (otp *OTP) ValidateOTP(email string, input string) error {
	// distinguish between an error with redis and when
	// rate is exceeded
	err := otp.RateLimitForOTPValidationExceeded(email)

	if err != nil {
		return err
	}

	stored, err := otp.getOTP(email)

	log.Debug().Msgf("validating %s %s %s", email, input, stored)

	if err == redis.Nil {
		return fmt.Errorf("no otp code found for email %s", email)
	} else if err != nil {
		return err
	}

	if stored != input {
		return fmt.Errorf("otp codes do not match for email %s", email)
	}

	// Remove after use
	err = otp.deleteOTP(email)

	if err != nil {
		return fmt.Errorf("failed to delete otp for email %s: %w", email, err)
	}

	return nil
}

// Limits the number of OTPs that can be sent by the system across all email addresses
// Returns true if rate limit exceeded along with an error.
// Returns false and an error if there was an error connecting to Redis.
// Returns false, nil if rate limit not exceeded.
func (otp *OTP) GlobalRateLimitForOTPCachingExceeded() error {

	attempts, err := otp.RedisClient.Incr(otp.Context, GlobalOtpMinuteRateKey).Result()

	if err != nil {
		return web.NewConnectionError(err.Error())
	}

	if attempts == 1 {
		// on first attempt set expiry
		otp.RedisClient.Expire(otp.Context, GlobalOtpMinuteRateKey, otp.globalRateLimit.Minute.BlockTime)
	}

	if attempts > otp.globalRateLimit.Minute.Limit {
		return NewRateLimitError("the global per minute rate limit for code generation has been exceeded")
	}

	attempts, err = otp.RedisClient.Incr(otp.Context, GlobalOtpHourRateKey).Result()

	if err != nil {
		return web.NewConnectionError(err.Error())
	}

	if attempts == 1 {
		// on first attempt set expiry
		otp.RedisClient.Expire(otp.Context, GlobalOtpHourRateKey, otp.globalRateLimit.Hour.BlockTime)
	}

	if attempts > otp.globalRateLimit.Hour.Limit {
		return NewRateLimitError("the global hourly rate limit for code generation has been exceeded")
	}

	attempts, err = otp.RedisClient.Incr(otp.Context, GlobalOtpDayRateKey).Result()

	if err != nil {
		return web.NewConnectionError(err.Error())
	}

	if attempts == 1 {
		// on first attempt set expiry
		otp.RedisClient.Expire(otp.Context, GlobalOtpDayRateKey, otp.globalRateLimit.Day.BlockTime)
	}

	if attempts > otp.globalRateLimit.Day.Limit {
		return NewRateLimitError("the global daily rate limit for code generation has been exceeded")
	}

	return nil
}

// limits the number of OTPs that can be sent to an email address
func (otp *OTP) RateLimitForOTPCachingExceeded(email string) error {
	key := fmt.Sprintf("otp:email:%s:send:attempts", email)

	attempts, err := otp.RedisClient.Incr(otp.Context, key).Result()

	if err != nil {
		return web.NewConnectionError(err.Error())
	}

	if attempts == 1 {
		// on first attempt set expiry
		otp.RedisClient.Expire(otp.Context, key, otp.rateLimit.BlockTime)
	}

	if attempts > otp.rateLimit.Limit {
		return NewRateLimitError("there have been too many attempts to create a code for this email address, please try again later")
	}

	return nil
}

// Returns true if rate limit exceeded
func (otp *OTP) RateLimitForOTPValidationExceeded(email string) error {
	key := fmt.Sprintf("otp:email:%s:check:attempts", email)

	attempts, err := otp.RedisClient.Incr(otp.Context, key).Result()

	if err != nil {
		return web.NewConnectionError(err.Error())
	}

	if attempts == 1 {
		// on first attempt set expiry
		otp.RedisClient.Expire(otp.Context, key, otp.rateLimit.BlockTime)
	}

	if attempts > otp.rateLimit.Limit {
		return NewRateLimitError("there have been too many attempts to validate a code for this email address, please try again later")
	}

	return nil
}

func Generate6DigitOTP() (string, error) {
	//max := big.NewInt(1000000) // 6 digits: 000000 - 999999

	n, err := rand.Int(rand.Reader, Otp6MaxNum)

	if err != nil {
		return "", err
	}

	// "%06d" padds with leading zeros if necessary
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func Generate8DigitOTP() (string, error) {
	//max := big.NewInt(1000000) // 6 digits: 000000 - 999999

	n, err := rand.Int(rand.Reader, Otp8MaxNum)

	if err != nil {
		return "", err
	}

	// "%08d" padds with leading zeros if necessary
	return fmt.Sprintf("%08d", n.Int64()), nil
}
