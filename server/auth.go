package server

import (
	"errors"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

var (
	accessTknSecret = "HiiHelloBiatch"
	refreshTknSecrt = "idiisjgooijdogojjon"
)

func CreateToken(userName string) (string, string, error) {
	accessTknClaims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 1)),
		Subject:   userName,
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTknClaims)
	SignedAccessToken, err := accessToken.SignedString([]byte(accessTknSecret))
	if err != nil {
		return "", "", err
	}
	refreshTknClaims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 2)),
		Subject:   userName,
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTknClaims)
	SignedRefreshToken, err := refreshToken.SignedString([]byte(refreshTknSecrt))
	if err != nil {
		return "", "", err
	}
	return SignedAccessToken, SignedRefreshToken, nil
}

func ValidateToken(signedToken, tokenType string) (*jwt.RegisteredClaims, error) {

	claims := &jwt.RegisteredClaims{}
	var secreat string
	if tokenType == "accessToken" {
		secreat = accessTknSecret
	} else {
		secreat = refreshTknSecrt
	}
	token, err := jwt.ParseWithClaims(signedToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(secreat), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		err = errors.New("error while parsing claims")
	}
	return claims, err
}
