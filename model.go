package openid

import (
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

var (
	DefaultScopes = []string{"openid", "email", "profile"}
	SessionName   = "openid"
)

type wellKnown struct {
	Issuer      string   `json:"issuer"`
	AuthUrl     string   `json:"authorization_endpoint"`
	TokenUrl    string   `json:"token_endpoint"`
	JWKSUrl     string   `json:"jwks_uri"`
	UserInfoUrl string   `json:"userinfo_endpoint"`
	Algorithms  []string `json:"id_token_signing_alg_values_supported"`
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
	jWKSUrl     string
	userInfoUrl string
	algorithms  []string
	store       *sessions.CookieStore
}
