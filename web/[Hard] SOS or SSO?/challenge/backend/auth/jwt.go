package auth

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"example.com/permnotes/database"
	"github.com/golang-jwt/jwt/v5"
)

var privateKey = []byte(os.Getenv("JWT_SECRET"))

func GenerateToken(user *database.User, ttl int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":      user.ID,
		"level":   user.Role.Level,
		"faction": user.FactionID,
		"iat":     time.Now().Unix(),
		"eat":     time.Now().Add(time.Second * time.Duration(ttl)).Unix(),
	})
	return token.SignedString(privateKey)
}

func ValidateJWT(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return privateKey, nil
	})
}

func getClaimsFromTokenString(tokenString string) (jwt.MapClaims, error) {
	token, err := ValidateJWT(tokenString)
	if err != nil {
		return jwt.MapClaims{}, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return jwt.MapClaims{}, errors.New("could not find claims")
	}

	if claims["eat"].(float64) < float64(time.Now().Unix()) {
		return jwt.MapClaims{}, errors.New("token expired")
	}

	return claims, nil
}

func GetUserIdFromToken(tokenString string) *uint64 {
	claims, err := getClaimsFromTokenString(tokenString)
	if err != nil {
		return nil
	}
	userId, ok := claims["id"]
	if !ok {
		return nil
	}
	id := uint64(userId.(float64))
	return &id
}

func AssertLevel(required int, tokenString string) bool {
	claims, err := getClaimsFromTokenString(tokenString)
	if err != nil {
		return false
	}
	level, ok := claims["level"]
	if !ok {
		return false
	}
	log.Println(level)
	return int(level.(float64)) >= required
}

type JWTClaims struct {
	UserID    uint64
	Level     int
	FactionID uint64
}

func GetJWTClaims(tokenString string) (*JWTClaims, error) {
	claims, err := getClaimsFromTokenString(tokenString)
	if err != nil {
		return nil, err
	}
	return &JWTClaims{
		UserID:    uint64(claims["id"].(float64)),
		Level:     int(claims["level"].(float64)),
		FactionID: uint64(claims["faction"].(float64)),
	}, nil
}
