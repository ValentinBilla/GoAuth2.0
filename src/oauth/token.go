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

type ClientInfo struct {
	ClientId     string `form:"client_id" binding:"required"`
	ClientSecret string `form:"client_secret"` // Will be ignored, currently Clients are all allowed by default.
}

type AccessTokenRequest struct {
	GrantType string `form:"grant_type" binding:"required,oneof=authorization_code refresh_token client_credentials"`
	ClientInfo
}

type AuthorizationCodeAccessTokenRequest struct {
	RedirectUri  string `form:"redirect_uri" binding:"required,url"`
	Code         string `form:"code" binding:"required"`
	CodeVerifier string `form:"code_verifier" binding:"required,min=43,max=128"`
	ClientInfo
}

type RefreshTokenAccessTokenRequest struct {
	RefreshToken string `form:"refresh_token" binding:"required"`
	ClientInfo
}

type TokenResponse struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	AccessToken  string `json:"access_token"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
}

func PostToken(c *gin.Context) {
	var request = AccessTokenRequest{}
	if err := c.ShouldBind(&request); err != nil {
		c.String(http.StatusBadRequest, err.Error())
		c.Abort()
		return
	}

	// No default as the GrantType should be validated on Binding
	switch request.GrantType {
	case "authorization_code":
		handleAuthorizationCodeAccessTokenRequest(c)
	case "refresh_token":
		handleRefreshTokenAccessTokenRequest(c)
	case "client_credentials":
		c.String(http.StatusNotImplemented, "Client Credentials Grant Type is not implemented")
		c.Abort()
		return
	}
}

func handleAuthorizationCodeAccessTokenRequest(c *gin.Context) {
	var request AuthorizationCodeAccessTokenRequest
	if err := c.ShouldBind(&request); err != nil {
		c.String(http.StatusBadRequest, err.Error())
		c.Abort()
		return
	}

	properties, err := infra.GetAuthorizationCode(request.Code)
	if err != nil {
		c.String(http.StatusBadRequest, "An error occurred while retrieving the authorization code")
		c.Abort()
		return
	}

	if properties.ClientId != request.ClientId || properties.RedirectUri != request.RedirectUri {
		c.String(http.StatusBadRequest, "Unrecognised client_id or redirect_uri")
		c.Abort()
		return
	}

	ok, err := verifyCodeChallenge(properties.CodeChallenge, properties.CodeChallengeMethod, request.CodeVerifier)
	if !ok || err != nil {
		c.String(http.StatusBadRequest, "Challenge verification failed")
		c.Abort()
		return
	}

	response, err := generateResponse(properties.ClientId, properties.ClientId, properties.Scope)
	if err != nil {
		c.String(http.StatusInternalServerError, "An error occurred while generating the response")
		c.Abort()
		return
	}

	c.JSON(http.StatusOK, response)
}

func handleRefreshTokenAccessTokenRequest(c *gin.Context) {
	var request RefreshTokenAccessTokenRequest
	if err := c.ShouldBind(&request); err != nil {
		c.String(http.StatusBadRequest, err.Error())
		c.Abort()
		return
	}

	properties, err := infra.GetRefreshToken(request.RefreshToken)
	if err != nil || properties.ClientId != request.ClientId {
		c.String(http.StatusBadRequest, "Unrecognised refresh token or client_id")
		c.Abort()
		return
	}

	if properties.IsValid != true {
		// If an error occurs here we cannot do anything
		_ = infra.CompromiseRefreshToken(request.RefreshToken)

		c.String(http.StatusInternalServerError, "Refresh token has already been used")
		c.Abort()
		return
	}

	if properties.ExpiresAt < time.Now().Unix() {
		c.String(http.StatusBadRequest, "Refresh token has expired")
		c.Abort()
		return
	}

	err = infra.InvalidateRefreshToken(request.RefreshToken)
	if err != nil {
		c.String(http.StatusInternalServerError, "An error occurred while invalidating the refresh token")
		c.Abort()
		return
	}

	response, err := generateResponse(properties.ClientId, properties.Username, properties.Scope)
	if err != nil {
		c.String(http.StatusInternalServerError, "An error occurred while generating the response")
		c.Abort()
		return
	}

	err = infra.SetRotatedToken(request.RefreshToken, response.AccessToken)
	if err != nil {
		c.String(http.StatusInternalServerError, "An error occurred while generating a new refresh token")
		c.Abort()
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
