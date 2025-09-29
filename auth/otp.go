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

const KEY = "otp:"

type RateLimit struct {
	Limit     int64         // number of allowed attempts
	BlockTime time.Duration // block time duration
}

type OTP struct {
	Context     context.Context
	RedisClient *redis.Client
	ttl         time.Duration
	rateLimit   RateLimit // max attempts allowed

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
	return NewOTP(rdb, TTL_10_MINS, RateLimit{Limit: 10, BlockTime: TTL_10_MINS})
}

func NewOTP(rdb *redis.Client, ttl time.Duration, rateLimit RateLimit) *OTP {
	return &OTP{
		Context:     context.Background(),
		RedisClient: rdb,
		ttl:         ttl,
		rateLimit:   rateLimit,
	}
}

// TTL returns the time to live duration for the OTP
func (otp *OTP) TTL() time.Duration {
	return otp.ttl
}

func (otp *OTP) Cache8DigitOTP(username string) (string, error) {

	code, err := Generate8DigitOTP() //Generate6DigitCode()

	if err != nil {
		return "", err
	}

	return otp.cacheOTP(username, code)
}

func (otp *OTP) Cache6DigitOTP(email string) (string, error) {

	code, err := Generate6DigitOTP() //Generate6DigitCode()

	if err != nil {
		return "", err
	}

	return otp.cacheOTP(email, code)
}

func (otp *OTP) cacheOTP(email string, code string) (string, error) {
	exceeded, err := otp.cacheOTPAttemptLimitExceeded(email)

	if err != nil {
		return "", err
	}

	if exceeded {
		return "", fmt.Errorf("too many attempts to create an OTP for this email address")
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

func (otp *OTP) ValidateOTP(email string, input string) (bool, error) {
	// distinguish between an error with redis and when
	// rate is exceeded
	exceeded, err := otp.validateOTPAttemptLimitExceeded(email)

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

// limits the number of OTPs that can be sent to an email address
func (otp *OTP) cacheOTPAttemptLimitExceeded(email string) (bool, error) {
	key := fmt.Sprintf("otp:email:%s:send:attempts", email)

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

func (otp *OTP) validateOTPAttemptLimitExceeded(email string) (bool, error) {
	key := fmt.Sprintf("opt:email:%s:check:attempts", email)

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
