package openid

import (
	"encoding/json"
	"errors"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"net/http"
	"time"
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
		issuer:      data.Issuer,
		userInfoUrl: data.UserInfoUrl,
		store:       sessions.NewCookieStore([]byte(opts.SessionSecret)),
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
		claims := Claims{}
		if err := json.Unmarshal(payload, &claims); err != nil {
			http.Error(w, "failed to unmarshal id token", http.StatusInternalServerError)
			return
		}
		if claims["aud"].(string) != c.oAuth2.ClientID {
			http.Error(w, "audience mismatch", http.StatusBadRequest)
			return
		}

		if claims["iss"].(string) != c.issuer {
			http.Error(w, "issuer mismatch", http.StatusBadRequest)
			return
		}

		if exp, ok := claims["exp"].(float64); ok {
			if time.Unix(int64(exp), 0).Before(time.Now()) {
				http.Error(w, "token expired", http.StatusBadRequest)
				return
			}
		} else {
			http.Error(w, "token expiration claim missing", http.StatusBadRequest)
			return
		}

		resp, err := client.Get(c.userInfoUrl)
		if err != nil {
			http.Error(w, "failed get user info", http.StatusBadRequest)
			return
		}
		defer resp.Body.Close()
		usrClaims := Claims{}
		if err := json.NewDecoder(resp.Body).Decode(&usrClaims); err != nil {
			http.Error(w, "failed to decode user info", http.StatusBadRequest)
			return
		}
		if claims["sub"] != usrClaims["sub"] {
			http.Error(w, "idToken and userInfo sub mismatch", http.StatusBadRequest)
			return
		}

		for k, v := range usrClaims {
			claims[k] = v
		}

		sess.Values["claims"] = claims
		if err := sess.Save(r, w); err != nil {
			http.Error(w, "failed to save session", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
	}
}

func (c *Config) GetClaims(r *http.Request) (Claims, error) {
	sess, err := c.store.Get(r, SessionName)
	if err != nil {
		return nil, err
	}
	if data, ok := sess.Values["claims"].(Claims); ok {
		return data, nil
	}
	return nil, nil
}
