package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/url"

	"example.com/permnotes/database"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

var ssoSessions = make(map[string]*SSOSession)

type SSOSession struct {
	FactionID int
	Config    *oauth2.Config
	Provider  *oidc.Provider
	Key       string
}

func GetRedirectUrlFromFaction(factionId int, redirectUrl string) string {
	config := database.FindOIDCConfigWithFaction(uint64(factionId))
	if config == nil {
		return "/login?error=Faction does not have a config"
	}
	provider, err := ValidateProviderEndpoint(config.Endpoint)
	if err != nil {
		log.Println("Failed to get provider: ", err)
		return config.Endpoint
	}
	key := fmt.Sprintf("%08x", rand.Uint64())
	ssoSession := &SSOSession{
		FactionID: factionId,
		Config: &oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  redirectUrl,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		Provider: provider,
		Key:      key,
	}
	ssoSessions[key] = ssoSession
	return ssoSession.Config.AuthCodeURL(key)
}

func ValidateProviderEndpoint(endpoint string) (*oidc.Provider, error) {
	ctx := context.Background()
	return oidc.NewProvider(ctx, endpoint)
}

func getSSOSessionFromKey(key string) *SSOSession {
	if session, ok := ssoSessions[key]; ok {
		return session
	}

	return nil
}

type SSOClaims struct {
	Email *string `json:"email"`
	Role  *string `json:"role"`
}

type tokenProvider struct {
	token *oauth2.Token
}

func (p *tokenProvider) Token() (*oauth2.Token, error) {
	return p.token, nil
}

func ProcessSSOCallback(values url.Values) (string, error) {
	key := values.Get("state")
	ssoSession := getSSOSessionFromKey(key)
	if ssoSession == nil {
		return "", errors.New("login failed")
	}

	ctx := context.Background()
	// Exchange the received code for a token
	oauth2Token, err := ssoSession.Config.Exchange(ctx, values.Get("code"))
	if err != nil {
		return "", errors.New("error getting token: " + err.Error())
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return "", errors.New("no token received")
	}

	// Parse and verify ID Token payload.
	oidcConfig := &oidc.Config{
		ClientID: ssoSession.Config.ClientID,
	}
	verifier := ssoSession.Provider.Verifier(oidcConfig)
	_, err = verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return "", errors.New("failed to verify ID Token: " + err.Error())
	}

	info, err := ssoSession.Provider.UserInfo(ctx, &tokenProvider{token: oauth2Token})
	if err != nil {
		return "", err
	}

	// Extract custom claims
	var claims SSOClaims
	if err := info.Claims(&claims); err != nil {
		return "", errors.New("invalid claims: " + err.Error())
	}

	if claims.Email == nil {
		return "", errors.New("email not returned from IdP")
	}

	ban := database.GetBan(*claims.Email)
	if ban != nil {
		return "", errors.New("you got banned!")
	}

	user := database.FindUserWithEmail(*claims.Email)
	if user == nil {
		user = RegisterUser(claims, ssoSession.FactionID)
	} else {
		if user.FactionID != uint64(ssoSession.FactionID) {
			return "", errors.New("wrong faction buddy")
		}
		log.Println("Logged in!", user.Email)
	}

	return GenerateToken(user, 1800)
}
