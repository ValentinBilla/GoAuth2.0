package main

import (
	"GoAuth2.0/authentication"
	"GoAuth2.0/clients"
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
	clients.InitClients()
	users.InitUsers()

	defer infra.CloseRedisClient()

	r := gin.Default()
	r.Static("/assets", "./resources/assets")
	r.StaticFile("/favicon.ico", "./resources/assets/favicon.ico")
	r.LoadHTMLGlob("./resources/templates/*")

	r.GET("/health", func(c *gin.Context) {
		c.String(200, "LIVE")
	})

	r.GET("/authorize", oauth.GetAuthorize)
	r.POST("/authorize", oauth.PostAuthorize)
	r.POST("/token", oauth.PostToken)

	// Test route to use generated access tokens
	photos := r.Group("/photos")
	photos.Use(authentication.JwtAuthenticationHandler("photos"))
	{
		photos.GET("/:id", mock_server.GetPhotoById)
	}

	if err := r.Run(); err != nil {
		log.Fatal(err)
	} // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}
