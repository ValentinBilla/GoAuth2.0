package authentication

import (
	"GoAuth2.0/oauth"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

func JwtAuthenticationHandler(scope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authorization := c.Request.Header.Get("Authorization")
		token, isBearer := strings.CutPrefix(authorization, "Bearer ")

		if authorization == "" || !isBearer {
			c.Set("WWW-Authenticate", fmt.Sprintf(`Bearer scope="%s"`, scope))
			c.String(http.StatusUnauthorized, "Missing token")
			c.Abort()
			return
		}

		claims, err := oauth.ParseAccessToken(token)
		if err != nil {
			c.String(http.StatusUnauthorized, "Invalid token")
			c.Abort()
			return
		}

		if scope != "" && !verifyScope(scope, claims.Scope) {
			c.String(http.StatusForbidden, "Insufficient scope")
			c.Abort()
		}

		c.Set("user", claims.Subject)
		c.Request.Header.Del("Authorization")
		c.Next()
	}
}

func verifyScope(requiredScope string, userScope string) bool {
	requiredScopes := strings.Split(requiredScope, " ")
	userScopes := strings.Split(userScope, " ")

	// We can afford O(nm) as n and m will most likely always be very small
	for _, reqScope := range requiredScopes {
		scopeFound := false
		for _, userScope := range userScopes {
			if reqScope == userScope {
				scopeFound = true
				break
			}
		}
		if !scopeFound {
			return false
		}
	}
	return true
}
