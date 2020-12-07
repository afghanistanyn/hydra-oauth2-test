package main

import (
	"crypto/rsa"
	"crypto/x509"
	pem2 "encoding/pem"
	"fmt"
	"github.com/dgrijalva/jwt-go"
)

func verifyToken(token string, key *rsa.PublicKey) error {

	jwtToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		pkcsPub, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, err
		}
		pem := pem2.EncodeToMemory(&pem2.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pkcsPub,
		})
		return jwt.ParseRSAPublicKeyFromPEM(pem)
	})
	if err != nil {
		return fmt.Errorf("Couldn't parse token: %v", err)
	}

	fmt.Printf("Header:\n%v\n", jwtToken.Header)
	fmt.Printf("Claims:\n%v\n", jwtToken.Claims)

	if !jwtToken.Valid {
		return fmt.Errorf("Token is invalid")
	}

	return nil
}
