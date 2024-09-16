package oauth

import (
	"GoAuth2.0/infra"
	"GoAuth2.0/utils"
	"crypto/sha256"
	"encoding/base64"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
	"time"
)

type AccessTokenRequest struct {
	GrantType string `form:"grant_type" binding:"required,oneof=authorization_code refresh_token client_credentials password"`
}

type AuthorizationCodeAccessTokenRequest struct {
	ClientId     string `form:"client_id" binding:"required"`
	RedirectUri  string `form:"redirect_uri" binding:"required,url"`
	Code         string `form:"code" binding:"required"`
	CodeVerifier string `form:"code_verifier"`
}

type RefreshTokenAccessTokenRequest struct {
	ClientId     string `form:"client_id" binding:"required"`
	RefreshToken string `form:"refresh_token" binding:"required"`
}

type TokenResponse struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	AccessToken  string `json:"access_token"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
}

func PostToken(c *gin.Context) {
	var request AuthorizationCodeAccessTokenRequest
	if err := c.ShouldBind(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	properties, err := infra.GetAuthorizationCode(request.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if properties.ClientId != request.ClientId || properties.RedirectUri != request.RedirectUri {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}

	if request.CodeVerifier != "" {
		if ok, err := verifyCodeChallenge(properties.CodeChallenge, properties.CodeChallengeMethod, request.CodeVerifier); !ok || err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
			return
		}
	}

	response, err := generateResponse(properties.ClientId, properties.ClientId, properties.Scope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

func generateResponse(username string, clientId string, scope string) (TokenResponse, error) {
	accessToken, err := generateAccessToken(username, scope)
	if err != nil {
		return TokenResponse{}, err
	}

	refreshToken, err := generateRefreshToken(clientId, username, scope)
	if err != nil {
		return TokenResponse{}, err
	}

	return TokenResponse{
		TokenType:    "Bearer",
		ExpiresIn:    int(utils.Config.OAuth.AccessTokenExpiration.Seconds()),
		AccessToken:  accessToken,
		Scope:        scope,
		RefreshToken: refreshToken,
	}, nil
}

func verifyCodeChallenge(challenge string, method string, verifier string) (bool, error) {

	switch method {
	case "plain":
		return challenge == verifier, nil
	case "S256":
		hash := sha256.Sum256([]byte(verifier))
		hashed := hash[:]
		encoded := base64.URLEncoding.EncodeToString(hashed)
		encoded = strings.TrimRight(encoded, "=")
		return encoded == challenge, nil
	default:
		return false, nil
	}
}

func generateRefreshToken(clientId string, username string, scope string) (string, error) {
	token := generateRandomCode()

	expiration := time.Now().Add(utils.Config.OAuth.RefreshTokenExpiration).Unix()
	properties := infra.RefreshTokenCachedProperties{
		ClientId:  clientId,
		Username:  username,
		Scope:     scope,
		ExpiresAt: expiration,
	}

	if err := infra.SaveRefreshToken(token, properties); err != nil {
		return "", err
	}
	return token, nil
}
