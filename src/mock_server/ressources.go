package mock_server

import "github.com/gin-gonic/gin"

func GetPhotoById(c *gin.Context) {
	id := c.Param("id")

	c.JSON(200, gin.H{
		"id": id,
	})
}
