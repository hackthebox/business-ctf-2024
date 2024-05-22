package models

type NewNoteModel struct {
	Title   string `json:"title" binding:"required"`
	Content string `json:"content" binding:"required"`
	Private bool   `json:"private"`
}

type UpdateContentModel struct {
	Content string `json:"content" binding:"required"`
}

type NewFactionModel struct {
	Name   string `json:"name" binding:"required"`
	Region string `json:"region" binding:"required"`
}

type NewOIDCConfigModel struct {
	ClientID     string `json:"clientId" binding:"required"`
	ClientSecret string `json:"clientSecret" binding:"required"`
	Endpoint     string `json:"endpoint" binding:"required"`
}

type ChooseFactionModel struct {
	ID int `json:"id" binding:"required"`
}
