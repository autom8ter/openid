package openid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
	"time"
)

var (
	DefaultScopes = []string{"openid", "email", "profile"}
)

type wellKnown struct {
	Issuer      string `json:"issuer"`
	AuthUrl     string `json:"authorization_endpoint"`
	TokenUrl    string `json:"token_endpoint"`
	UserInfoUrl string `json:"userinfo_endpoint"`
}

type Opts struct {
	WellKnownUrl string
	ClientID     string
	ClientSecret string
	Redirect     string
	Scopes       []string
}

type Config struct {
	oAuth2      *oauth2.Config
	issuer      string
	userInfoUrl string
}

type OpenID struct {
	UserInfo  map[string]interface{}
	IDToken   map[string]interface{}
	AuthToken *oauth2.Token
}

func NewConfig(opts *Opts) (*Config, error) {
	if len(opts.Scopes) == 0 {
		opts.Scopes = DefaultScopes
	}
	if opts.ClientID == "" {
		return nil, errors.New("[Config] empty clientID")
	}
	if opts.ClientSecret == "" {
		return nil, errors.New("[Config] empty client secret")
	}
	resp, err := http.Get(opts.WellKnownUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data := &wellKnown{}
	if err := json.NewDecoder(resp.Body).Decode(data); err != nil {
		return nil, fmt.Errorf("[Config] decoding well known: %s", err.Error())
	}
	return &Config{
		oAuth2: &oauth2.Config{
			ClientID:     opts.ClientID,
			ClientSecret: opts.ClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  data.AuthUrl,
				TokenURL: data.TokenUrl,
			},
			RedirectURL: opts.Redirect,
			Scopes:      opts.Scopes,
		},
		issuer:      data.Issuer,
		userInfoUrl: data.UserInfoUrl,
	}, nil
}

func (c *Config) OAuth2() *oauth2.Config {
	return c.oAuth2
}

func (c *Config) UserInfoUrl() string {
	return c.userInfoUrl
}

func (c *Config) Issuer() string {
	return c.issuer
}

func (c *Config) RedirectLoginURL(w http.ResponseWriter, r *http.Request, state string) {
	http.Redirect(w, r, c.oAuth2.AuthCodeURL(state), http.StatusTemporaryRedirect)
}

func (c *Config) GetOpenID(ctx context.Context, code string) (*OpenID, error) {
	oauth2Token, err := c.oAuth2.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("[Access Token] %s", err.Error())
	}
	client := c.oAuth2.Client(ctx, oauth2Token)
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("[Access Token] missing id_token")
	}
	payload, err := parseJWT(rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("[Id Token] %s", err.Error())
	}
	idToken := map[string]interface{}{}
	if err := json.Unmarshal(payload, &idToken); err != nil {
		return nil, fmt.Errorf("[Id Token] %s", err.Error())
	}
	if aud, ok := idToken["aud"].(string); ok {
		if aud != c.oAuth2.ClientID {
			return nil, fmt.Errorf("[Id Token] audience mismatch: %s != %s", aud, c.oAuth2.ClientID)
		}
	} else {
		return nil, errors.New("[Id Token] missing aud claim")
	}

	if iss, ok := idToken["iss"].(string); ok {
		if iss != c.issuer {
			return nil, fmt.Errorf("[Id Token] issuer mismatch: %s != %s", iss, c.issuer)
		}
	} else {
		return nil, errors.New("[Id Token] missing iss claim")
	}

	if exp, ok := idToken["exp"].(float64); ok {
		if time.Unix(int64(exp), 0).Before(time.Now()) {
			return nil, errors.New("[Id Token] id token expired")
		}
	} else {
		return nil, errors.New("[Id Token] missing exp claim")
	}
	if idToken["sub"] == nil {
		return nil, errors.New("[Id Token] missing sub claim")
	}
	resp, err := client.Get(c.userInfoUrl)
	if err != nil {
		return nil, fmt.Errorf("[User Info] failed to get user info: %s", err.Error())
	}
	defer resp.Body.Close()
	usrClaims := map[string]interface{}{}
	if err := json.NewDecoder(resp.Body).Decode(&usrClaims); err != nil {
		return nil, fmt.Errorf("[User Info] failed to decode user info: %s", err.Error())
	}

	if idToken["sub"] != usrClaims["sub"] {
		return nil, fmt.Errorf("[User Info] sub mismatch: %v != %s", idToken["sub"], usrClaims["sub"])
	}
	return &OpenID{
		UserInfo:  usrClaims,
		IDToken:   idToken,
		AuthToken: oauth2Token,
	}, nil
}
