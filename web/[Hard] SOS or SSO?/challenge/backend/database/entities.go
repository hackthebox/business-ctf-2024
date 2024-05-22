package database

import "gorm.io/gorm"

const (
	USER_LEVEL = iota
	SUPPORT_LEVEL
	ADMIN_LEVEL
)

type Role struct {
	ID    uint64
	Name  string `gorm:"unique"`
	Level int
}

type User struct {
	gorm.Model
	Email     string `gorm:"unique"`
	RoleID    uint64
	Role      Role
	FactionID uint64
	Faction   Faction
}

type Faction struct {
	ID     uint64
	Name   string
	Region string
}

type OIDCConfig struct {
	gorm.Model
	ClientID     string
	ClientSecret string
	Endpoint     string
	FactionID    uint64 `gorm:"unique"`
	Faction      Faction
}

type Note struct {
	gorm.Model
	Title    string
	Content  string
	AuthorID *uint64
	Author   *User
	Private  bool
}

type Ban struct {
	Email string `gorm:"primaryKey"`
}
