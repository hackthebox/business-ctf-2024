package endpoints

import (
	"strconv"

	"example.com/permnotes/auth"
	"example.com/permnotes/database"
	"example.com/permnotes/models"
	"github.com/gin-gonic/gin"
)

func CreateFaction(c *gin.Context) {
	var newFaction models.NewFactionModel
	err := c.BindJSON(&newFaction)
	if err != nil {
		c.JSON(400, gin.H{
			"message": "Invalid faction content!",
		})
		return
	}
	faction := database.CreateNewFaction(
		newFaction.Name,
		newFaction.Region,
	)
	c.JSON(200, gin.H{
		"id": faction.ID,
	})
}

func GetFactionData(c *gin.Context) {
	faction := getFactionFromUrl(c)
	if faction == nil {
		return
	}
	data := models.FactionModel{
		ID:     faction.ID,
		Name:   faction.Name,
		Region: faction.Region,
		Config: nil,
	}
	config := database.FindOIDCConfigWithFaction(faction.ID)
	if config != nil {
		data.Config = &models.FactionConfigModel{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Endpoint:     config.Endpoint,
		}
	}
	c.JSON(200, data)
}

func CreateOIDCConfig(c *gin.Context) {
	faction := getFactionFromUrl(c)
	if faction == nil {
		return
	}
	var newConfig models.NewOIDCConfigModel
	err := c.BindJSON(&newConfig)
	if err != nil {
		c.JSON(400, gin.H{
			"message": "Invalid config content!",
		})
		return
	}
	_, err = auth.ValidateProviderEndpoint(newConfig.Endpoint)
	if err != nil {
		c.JSON(400, gin.H{
			"message": err.Error(),
		})
		return
	}
	config := database.FindOIDCConfigWithFaction(faction.ID)
	if config != nil {
		config.ClientID = newConfig.ClientID
		config.ClientSecret = newConfig.ClientSecret
		config.Endpoint = newConfig.Endpoint
		database.UpdateOIDCConfig(config)
	} else {
		config = database.CreateNewOIDCConfig(
			newConfig.ClientID,
			newConfig.ClientSecret,
			newConfig.Endpoint,
			faction.ID,
		)
	}
	c.JSON(200, gin.H{
		"id": config.ID,
	})
}

func getFactionFromUrl(c *gin.Context) *database.Faction {
	factionId, err := strconv.Atoi(c.Param("factionId"))
	if err != nil {
		c.JSON(404, gin.H{
			"message": "Faction not found!",
		})
		c.Abort()
		return nil
	}
	faction := database.FindFactionWithId(factionId)
	if faction == nil {
		c.JSON(404, gin.H{
			"message": "Faction not found!",
		})
		c.Abort()
		return nil
	}

	return faction
}
