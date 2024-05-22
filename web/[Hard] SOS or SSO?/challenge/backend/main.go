package main

import (
	"math/rand"
	"time"

	"example.com/permnotes/database"
	"example.com/permnotes/endpoints"
	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
)

func main() {
	rand.Seed(time.Now().UnixNano())
	database.InitDB()
	database.PrepareDatabase()
	r := gin.Default()
	// Serve the frontend
	r.Use(static.Serve("/", static.LocalFile("../frontend/dist/", true)))
	r.NoRoute(func(c *gin.Context) {
		c.File("../frontend/dist/index.html")
	})

	r.Use(endpoints.CsrfMiddleware)
	// Authentication
	authentication := r.Group("/auth")
	authentication.GET("/sso/factions", endpoints.GetAvailableFactions)
	authentication.POST("/sso", endpoints.FactionSSO)
	authentication.GET("/sso/callback", endpoints.FactionSSOCallback)
	authentication.GET("/logout", endpoints.Logout)

	// Main api
	api := r.Group("/api")
	api.Use(endpoints.UserMiddleware)
	{
		api.GET("/user", endpoints.GetCurrentUser)
		// Notes
		api.GET("/notes", endpoints.GetNotes)
		api.POST("/note", endpoints.CreateNote)
		api.GET("/note/:noteId", endpoints.GetNote)
		api.PATCH("/note/:noteId", endpoints.UpdateNote)
		api.POST("/note/:noteId/report", endpoints.ReportNote)
		api.DELETE("/note/:noteId", endpoints.RemoveNote)
	}
	// Support routes
	support := api.Group("/support")
	support.Use(endpoints.SupportMiddleware)
	{
		support.POST("/faction", endpoints.CreateFaction)
		support.GET("/faction/:factionId", endpoints.GetFactionData)
		support.POST("/faction/:factionId/config", endpoints.CreateOIDCConfig)
	}
	// Admin routes
	admin := api.Group("/admin")
	admin.Use(endpoints.AdminMiddleware)
	{
		admin.GET("/users", endpoints.GetUsers)
		admin.POST("/users/:userId/ban", endpoints.BanUser)
	}

	r.Run(":8080")
}
