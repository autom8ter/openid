package openid

import (
	"encoding/json"
	"errors"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"net/http"
)

func NewConfig(opts *Opts) (*Config, error) {
	if len(opts.Scopes) == 0 {
		opts.Scopes = DefaultScopes
	}
	if opts.ClientID == "" {
		return nil, errors.New("empty clientID")
	}
	if opts.ClientSecret == "" {
		return nil, errors.New("empty client secret")
	}
	resp, err := http.Get(opts.WellKnownUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data := &wellKnown{}
	if err := json.NewDecoder(resp.Body).Decode(data); err != nil {
		return nil, err
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
		jWKSUrl:     data.JWKSUrl,
		userInfoUrl: data.UserInfoUrl,
		algorithms:  data.Algorithms,
		store:       sessions.NewCookieStore([]byte(opts.SessionSecret)),
	}, nil
}

func (c *Config) OAuth2() *oauth2.Config {
	return c.oAuth2
}

func (c *Config) JWKSUrl() string {
	return c.jWKSUrl
}

func (c *Config) UserInfoUrl() string {
	return c.userInfoUrl
}

func (c *Config) Algorithms() []string {
	return c.algorithms
}

func (c *Config) CookieStore() *sessions.CookieStore {
	return c.store
}

func (c *Config) HandleRedirect() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, c.oAuth2.AuthCodeURL(""), http.StatusFound)
	}
}

func (c *Config) Login(redirect string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := c.store.Get(r, SessionName)
		if err != nil {
			http.Error(w, "failed to get session", http.StatusBadRequest)
			return
		}
		defer sess.Save(r, w)
		oauth2Token, err := c.oAuth2.Exchange(r.Context(), r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "failed to exchange authorization code", http.StatusBadRequest)
			return
		}
		client := c.oAuth2.Client(r.Context(), oauth2Token)
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "id token not found", http.StatusBadRequest)
			return
		}
		payload, err := parseJWT(rawIDToken)
		if err != nil {
			http.Error(w, "failed to parse id token", http.StatusBadRequest)
			return
		}
		idToken := Data{}
		if err := json.Unmarshal(payload, &idToken); err != nil {
			http.Error(w, "failed to unmarshal id token", http.StatusInternalServerError)
			return
		}
		sess.Values["idToken"] = idToken
		resp, err := client.Get(c.userInfoUrl)
		if err != nil {
			http.Error(w, "failed get user info", http.StatusBadRequest)
			return
		}
		defer resp.Body.Close()
		usr := Data{}
		if err := json.NewDecoder(resp.Body).Decode(&usr); err != nil {
			http.Error(w, "failed to decode user info", http.StatusBadRequest)
			return
		}
		sess.Values["usrInfo"] = usr
		http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
	}
}

func (c *Config) GetIDToken(r *http.Request) (Data, error) {
	sess, err := c.store.Get(r, SessionName)
	if err != nil {
		return nil, err
	}
	if data, ok := sess.Values["idToken"].(Data); ok {
		return data, nil
	}
	return nil, nil
}

func (c *Config) GetUsrInfo(r *http.Request) (Data, error) {
	sess, err := c.store.Get(r, SessionName)
	if err != nil {
		return nil, err
	}
	if data, ok := sess.Values["usrInfo"].(Data); ok {
		return data, nil
	}
	return nil, nil
}
