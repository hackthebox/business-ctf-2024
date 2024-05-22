package endpoints

import (
	"example.com/permnotes/auth"
	"example.com/permnotes/database"
	"github.com/gin-gonic/gin"
)

func getTokenFromRequest(c *gin.Context) string {
	token, err := c.Cookie("notesToken")
	if err != nil {
		return ""
	}
	return token
}

func GetUserClaims(c *gin.Context) *auth.JWTClaims {
	claims, ok := c.Get("user")
	if claims == nil || !ok {
		return nil
	}

	return claims.(*auth.JWTClaims)
}

func CsrfMiddleware(c *gin.Context) {
	if c.Request.Method == "GET" || c.Request.Method == "HEAD" {
		return
	}
	if c.Request.Header.Get("X-NOTES-CSRF-PROTECTION") != "1" {
		c.JSON(401, gin.H{
			"message": "CSRF protection missing",
		})
		c.Abort()
	}
}

func UserMiddleware(c *gin.Context) {
	rawToken := getTokenFromRequest(c)
	if rawToken == "" {
		c.Set("user", nil)
		return
	}
	claims, err := auth.GetJWTClaims(rawToken)
	if err != nil {
		c.JSON(401, gin.H{
			"message": err.Error(),
		})
		c.Abort()
		return
	}
	c.Set("user", claims)
}

func SupportMiddleware(c *gin.Context) {
	claims, ok := c.Get("user")
	if claims == nil || !ok {
		c.JSON(401, gin.H{
			"message": "Unauthorized",
		})
		c.Abort()
		return
	}
	if claims.(*auth.JWTClaims).Level < database.SUPPORT_LEVEL {
		c.JSON(403, gin.H{
			"message": "Only support users and above can take such action",
		})
		c.Abort()
	}
}

func AdminMiddleware(c *gin.Context) {
	claims, ok := c.Get("user")
	if claims == nil || !ok {
		c.JSON(401, gin.H{
			"message": "Unauthorized",
		})
		c.Abort()
		return
	}
	if claims.(*auth.JWTClaims).Level < database.ADMIN_LEVEL {
		c.JSON(403, gin.H{
			"message": "Only support users and above can take such action",
		})
		c.Abort()
	}
}
