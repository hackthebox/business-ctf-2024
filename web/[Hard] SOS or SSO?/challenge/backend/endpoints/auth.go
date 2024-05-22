package endpoints

import (
	"fmt"
	"net/http"
	"strings"

	"example.com/permnotes/auth"
	"example.com/permnotes/database"
	"example.com/permnotes/models"
	"github.com/gin-gonic/gin"
)

func ssoError(c *gin.Context, err string) {
	c.Redirect(http.StatusFound, "/login?error="+err)
}

func getRedirectUrl(request *http.Request) string {
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}

	return fmt.Sprintf("%s://%s/auth/sso/callback", scheme, request.Host)
}

func FactionSSO(c *gin.Context) {
	// Get faction from request
	var faction models.ChooseFactionModel
	err := c.BindJSON(&faction)
	if err != nil {
		c.JSON(400, gin.H{
			"message": "Invalid faction!",
		})
		return
	}
	// Get sso parameters
	redirectUrl := auth.GetRedirectUrlFromFaction(
		faction.ID,
		getRedirectUrl(c.Request),
	)
	c.JSON(200, models.SSORedirectModel{Url: redirectUrl})
}

func FactionSSOCallback(c *gin.Context) {
	token, err := auth.ProcessSSOCallback(c.Request.URL.Query())
	if err != nil {
		ssoError(c, err.Error())
		return
	}
	c.SetCookie(
		"notesToken",
		token,
		1800,
		"/",
		strings.Split(c.Request.Host, ":")[0],
		false,
		true,
	)
	c.Redirect(http.StatusFound, "/app")
}

func GetAvailableFactions(c *gin.Context) {
	factionModels := []models.FactionModel{}
	for _, config := range database.GetOIDCConfigs() {
		factionModels = append(
			factionModels,
			models.FactionModel{
				ID:     config.Faction.ID,
				Name:   config.Faction.Name,
				Region: config.Faction.Region,
				Config: nil,
			},
		)
	}
	c.JSON(200, factionModels)
}

func Logout(c *gin.Context) {
	c.SetCookie(
		"notesToken",
		"",
		-1,
		"/",
		strings.Split(c.Request.Host, ":")[0],
		false,
		true,
	)
	c.Redirect(http.StatusFound, "/app")
}

func GetCurrentUser(c *gin.Context) {
	userClaims := GetUserClaims(c)
	if userClaims == nil {
		c.JSON(401, gin.H{
			"message": "Unauthorized",
		})
		return
	}
	user := database.FindUserWithId(int(userClaims.UserID))
	if user == nil {
		c.JSON(401, gin.H{
			"message": "Unauthorized",
		})
		return
	}
	c.JSON(200, models.UserModel{
		ID:      user.ID,
		Email:   user.Email,
		Role:    user.Role.Name,
		Faction: user.Faction.Name,
	})
}
