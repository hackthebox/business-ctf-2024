package auth

import (
	"example.com/permnotes/database"
)

func RegisterUser(claims SSOClaims, factionId int) *database.User {
	var roleName string
	if claims.Role == nil {
		roleName = "user"
	} else {
		roleName = *claims.Role
	}
	role := database.FindRoleWithName(roleName)
	return database.CreateNewUser(*claims.Email, *role, uint64(factionId))
}
