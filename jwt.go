package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const TOKEN_TYPE_ACCESS string = "access"
const TOKEN_TYPE_REFRESH string = "refresh"
const TOKEN_TYPE_OTP string = "otp"

const TOKEN_TYPE_ACCESS_TTL time.Duration = time.Hour
const TOKEN_TYPE_OTP_TTL time.Duration = time.Minute * 20
const TOKEN_TYPE_REFRESH_TTL_DAYS = 7

type JwtCustomClaims struct {
	UserId string `json:"userId"`
	//Name  string `json:"name"`
	Type   string `json:"type"`
	IpAddr string `json:"ipAddr"`
	jwt.RegisteredClaims
}

type JwtOtpCustomClaims struct {
	OTP string `json:"otp"`
	JwtCustomClaims
}

func CreateOtpJwt(userId string, otp string, ipAddr string, secret string) (string, error) {

	// Set custom claims
	claims := JwtOtpCustomClaims{
		JwtCustomClaims: JwtCustomClaims{UserId: userId, Type: TOKEN_TYPE_OTP, IpAddr: ipAddr, RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(TOKEN_TYPE_OTP_TTL)),
		}},
		OTP: otp,
	}

	return CreateToken(claims, secret)
}

func CreateAccessToken(userId string, ipAddr string, secret string) (string, error) {

	// Set custom claims
	claims := JwtCustomClaims{
		UserId:           userId,
		IpAddr:           ipAddr,
		Type:             TOKEN_TYPE_ACCESS,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(TOKEN_TYPE_ACCESS_TTL))},
	}

	return CreateToken(claims, secret)
}

func CreateRefreshToken(userId string, ipAddr string, secret string) (string, error) {

	// Set custom claims
	claims := JwtCustomClaims{
		UserId:           userId,
		IpAddr:           ipAddr,
		Type:             TOKEN_TYPE_REFRESH,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().AddDate(0, 0, TOKEN_TYPE_REFRESH_TTL_DAYS))},
	}

	return CreateToken(claims, secret)
}

func CreateToken(claims jwt.Claims, secret string) (string, error) {

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate encoded token and send it as response.
	t, err := token.SignedString([]byte(secret))

	if err != nil {
		return "", err
	}

	return t, nil
}
