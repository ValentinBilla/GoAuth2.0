package main

import (
	"GoAuth2.0/authentication"
	"GoAuth2.0/infra"
	"GoAuth2.0/mock_server"
	"GoAuth2.0/oauth"
	"GoAuth2.0/users"
	"GoAuth2.0/utils"
	"github.com/gin-gonic/gin"
	"log"
)

func main() {
	utils.LoadConfiguration()
	users.InitUsers()
	defer infra.CloseRedisClient()

	r := gin.Default()
	r.LoadHTMLGlob("templates/*")

	r.GET("/authorize", oauth.GetAuthorize)
	r.POST("/authorize", oauth.PostAuthorize)
	r.POST("/token", oauth.PostToken)

	// Test route to use generated access tokens
	scopes := r.Group("/resources/photos")
	scopes.Use(authentication.JwtAuthenticationHandler("photos"))
	{
		scopes.GET("/:id", mock_server.GetPhotoById)
	}

	if err := r.Run(); err != nil {
		log.Fatal(err)
	} // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}
