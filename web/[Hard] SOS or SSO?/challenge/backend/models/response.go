package models

import "time"

type NoteModel struct {
	ID        uint      `json:"id"`
	Title     string    `json:"title"`
	Content   string    `json:"content"`
	Author    string    `json:"author"`
	Private   bool      `json:"private"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type FactionModel struct {
	ID     uint64              `json:"id"`
	Name   string              `json:"name"`
	Region string              `json:"region"`
	Config *FactionConfigModel `json:"config"`
}

type FactionConfigModel struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	Endpoint     string `json:"endpoint"`
}

type UserModel struct {
	ID      uint   `json:"id"`
	Email   string `json:"email"`
	Role    string `json:"role"`
	Faction string `json:"faction"`
}

type SSORedirectModel struct {
	Url string `json:"url"`
}
