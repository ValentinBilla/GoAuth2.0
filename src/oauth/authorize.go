package oauth

import (
	"GoAuth2.0/infra"
	"GoAuth2.0/users"
	"crypto/rand"
	"encoding/base64"
	"github.com/alexedwards/argon2id"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

type authorizationGrantRequest struct {
	ResponseType string `form:"response_type" binding:"required,oneof=code token"`
	ClientId     string `form:"client_id" binding:"required"`
	ClientSecret string `form:"client_secret"`
	RedirectUri  string `form:"redirect_uri" binding:"required,url"`
	Scope        string `form:"scope"`
	State        string `form:"state" binding:"required"`

	CodeChallenge       string `form:"code_challenge" binding:"required,if=CodeChallengeMethod=plain"`
	CodeChallengeMethod string `form:"code_challenge_method" binding:"required,oneof=plain S256"`

	Username string `form:"username"`
	Password string `form:"password"`
}

func GetAuthorize(c *gin.Context) {
	var request authorizationGrantRequest
	if err := c.ShouldBind(&request); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.HTML(http.StatusOK, "authorize.gohtml", gin.H{
		"clientId": request.ClientId,
		"scopes":   strings.Split(request.Scope, "+"),
	})
}

func PostAuthorize(c *gin.Context) {

	var request authorizationGrantRequest
	if err := c.ShouldBind(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if request.ResponseType == "token" {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "response_type token"})
		return
	}

	user := users.GetUser(request.Username)
	if user.Username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	match, _, err := argon2id.CheckHash(request.Password, user.Hash)
	// TODO: Implement re-hash in case of too weak hashing cost parameters
	if !match || err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	code, err := generateAuthorizationGrantCode(request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	redirectUrl := request.RedirectUri
	redirectUrl += "?state=" + request.State
	redirectUrl += "&code=" + code

	c.Redirect(http.StatusFound, redirectUrl)
}

func generateAuthorizationGrantCode(request authorizationGrantRequest) (string, error) {
	code := generateRandomCode()
	properties := infra.AuthorizationCodeCachedProperties{
		ClientId:            request.ClientId,
		RedirectUri:         request.RedirectUri,
		Username:            request.Username,
		Scope:               request.Scope,
		CodeChallenge:       request.CodeChallenge,
		CodeChallengeMethod: request.CodeChallengeMethod,
	}

	if err := infra.SaveAuthorizationCode(code, properties); err != nil {
		return "", err
	}

	return code, nil
}

func generateRandomCode() string {
	randomBytes := make([]byte, 32)
	_, _ = rand.Read(randomBytes)

	code := base64.URLEncoding.EncodeToString(randomBytes)
	return strings.TrimRight(code, "=")
}
