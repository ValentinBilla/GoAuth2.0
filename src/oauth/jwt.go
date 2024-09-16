package oauth

import (
	"GoAuth2.0/utils"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"strings"
	"time"
)

type AccessTokenClaims struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

func generateAccessToken(username string, scope string) (string, error) {
	expiresAt := time.Now().Add(utils.Config.OAuth.AccessTokenExpiration)
	claims := AccessTokenClaims{
		Scope: strings.ReplaceAll(scope, "+", " "),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    utils.Config.JWT.Issuer,
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(utils.Config.JWT.SecretKey))
}

func ParseAccessToken(tokenString string) (AccessTokenClaims, error) {
	signingMethods := []string{jwt.SigningMethodHS256.Alg()}

	token, err := jwt.ParseWithClaims(
		tokenString, &AccessTokenClaims{},
		getHMACSecretKey,
		jwt.WithValidMethods(signingMethods),
		jwt.WithIssuer(utils.Config.JWT.Issuer),
	)
	if err != nil {
		return AccessTokenClaims{}, err
	}

	claims, ok := token.Claims.(*AccessTokenClaims)
	if !ok {
		return AccessTokenClaims{}, errors.New("type assertion failed for claims")
	}

	return *claims, nil
}

func getHMACSecretKey(token *jwt.Token) (interface{}, error) {
	return []byte(utils.Config.JWT.SecretKey), nil
}
