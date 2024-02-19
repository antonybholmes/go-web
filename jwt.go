package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JwtCustomClaims struct {
	UserId string `json:"userId"`
	//Name  string `json:"name"`
	//Email string `json:"email"`
	IpAddr string `json:"ipAddr"`
	jwt.RegisteredClaims
}

type JwtOtpCustomClaims struct {
	OTP string `json:"otp"`
	JwtCustomClaims
}

func CreateOtpJwt(user *AuthUser, otp string, ipAddr string, secret string) (string, error) {

	// Set custom claims
	claims := JwtOtpCustomClaims{
		JwtCustomClaims: JwtCustomClaims{UserId: user.UserId, IpAddr: ipAddr, RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 30)),
		}},
		OTP: otp,
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate encoded token and send it as response.
	t, err := token.SignedString([]byte(secret))

	if err != nil {
		return "", err
	}

	return t, nil
}
