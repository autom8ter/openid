package openid

import (
	"encoding/gob"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

func init() {
	gob.Register(&Claims{})
}

var (
	DefaultScopes = []string{"openid", "email", "profile"}
	SessionName   = "openid"
)

type wellKnown struct {
	Issuer      string `json:"issuer"`
	AuthUrl     string `json:"authorization_endpoint"`
	TokenUrl    string `json:"token_endpoint"`
	UserInfoUrl string `json:"userinfo_endpoint"`
}

type Opts struct {
	SessionSecret string
	WellKnownUrl  string
	ClientID      string
	ClientSecret  string
	Redirect      string
	Scopes        []string
}

type Config struct {
	oAuth2      *oauth2.Config
	issuer      string
	userInfoUrl string
	store       *sessions.CookieStore
}

type Claims map[string]interface{}
