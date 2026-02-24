package middleware

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type (
	JwtClaimsParser interface {
		Parse(token string, claims jwt.Claims) error
	}

	JwtClaimsRSAParser struct {
		PublicKey *rsa.PublicKey
	}

	JwtClaimsES256Parser struct {
		PublicKey *ecdsa.PublicKey
	}

	JwtClaimsHMACParser struct {
		Secret []byte
	}
)

func NewJwtClaimsRSAParser(publicKey *rsa.PublicKey) *JwtClaimsRSAParser {
	return &JwtClaimsRSAParser{PublicKey: publicKey}
}

func (p *JwtClaimsRSAParser) Parse(token string, claims jwt.Claims) error {
	// Parse the JWT
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		// Return the secret key for verifying the token
		return p.PublicKey, nil
	})

	return err
}

// Given a public key and a token, it will parse the token and return the claims
// stored within it
func NewJwtClaimsES256Parser(publicKey *ecdsa.PublicKey) *JwtClaimsES256Parser {
	return &JwtClaimsES256Parser{PublicKey: publicKey}
}

func (p *JwtClaimsES256Parser) Parse(token string, claims jwt.Claims) error {
	// Parse the JWT
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		// Return the secret key for verifying the token
		return p.PublicKey, nil
	})

	return err
}

func NewJwtClaimsHMACParser(secret string) *JwtClaimsHMACParser {
	return &JwtClaimsHMACParser{Secret: []byte(secret)}
}

func (p *JwtClaimsHMACParser) Parse(token string, claims jwt.Claims) error {
	hmacSecret := p.Secret

	// Parse the JWT
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)

		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return hmacSecret, nil
	})

	return err
}
