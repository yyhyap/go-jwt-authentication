package main

import (
	helper "golang-jwt-project/helpers"
	routes "golang-jwt-project/routes"

	"github.com/gin-gonic/gin"
)

func main() {

	// var port string = os.Getenv("PORT")

	port := helper.GetEnvVariable("PORT")

	if port == "" {
		port = "8080"
	}

	router := gin.New()
	router.Use(gin.Logger())

	routes.AuthRoutes(router)
	routes.UserRoutes(router)

	// router handling function
	router.GET("/api-1", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"success": "Access granted for api-1",
		})
	})

	router.GET("/api-2", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"success": "Access granted for api-2",
		})
	})

	router.Run(":" + port)
}
