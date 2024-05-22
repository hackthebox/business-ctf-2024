package endpoints

import (
	"strconv"

	"example.com/permnotes/database"
	"example.com/permnotes/models"
	"github.com/gin-gonic/gin"
)

func GetUsers(c *gin.Context) {
	users := database.GetUsers()
	userModels := []models.UserModel{}
	for _, u := range users {
		userModels = append(
			userModels,
			models.UserModel{
				ID:      u.ID,
				Email:   u.Email,
				Role:    u.Role.Name,
				Faction: u.Faction.Name,
			},
		)
	}
	c.JSON(200, userModels)
}

func BanUser(c *gin.Context) {
	userId, err := strconv.Atoi(c.Param("userId"))
	if err != nil {
		c.JSON(400, gin.H{
			"message": "Invalid user id",
		})
		return
	}
	user := database.FindUserWithId(userId)
	if user == nil {
		c.JSON(404, gin.H{
			"message": "User not found",
		})
		return
	}
	database.BanEmail(user.Email)
	database.DeleteUser(user)
	c.JSON(204, gin.H{})
}
