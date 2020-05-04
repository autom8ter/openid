//go:generate godocdown -o README.md

package openid

import (
	"context"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"net/http"
	"strings"
	"time"
)

func init() {
	gob.Register(&User{})
	session = sessions.NewCookieStore([]byte("default_secret"))
}

const sessionName = "openid"

var (
	session *sessions.CookieStore
	//DefaultScopes are added if a Configs scopes are empty, they include: openid, email, profile
	DefaultScopes = []string{"openid", "email", "profile"}
)

//SetSession overrides the default session store(recommended for production usage)
func SetSession(store *sessions.CookieStore) {
	session = store
}

//User is a combination of the IDToken and the data returned from the UserInfo endpoint
type User struct {
	IDToken  map[string]interface{} `json:"id_token"`
	UserInfo map[string]interface{} `json:"user_info"`
}

func (o *User) String() string {
	bits, _ := json.MarshalIndent(o, "", "    ")
	return string(bits)
}

type OnLoginFunc func(u *AuthUser, r *http.Request) error

type wellKnown struct {
	Issuer      string `json:"issuer"`
	AuthUrl     string `json:"authorization_endpoint"`
	TokenUrl    string `json:"token_endpoint"`
	UserInfoUrl string `json:"userinfo_endpoint"`
}

//Opts are options used when creating a new Configuration
type Opts struct {
	// OpenID Connect describes a metadata document that contains most of the information required for an app to do sign-in.
	// ex: https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration
	DiscoveryUrl string
	// ClientID is the application's ID.
	ClientID string
	// ClientSecret is the application's secret.
	ClientSecret string
	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	Redirect string
	// Scope specifies optional requested permissions.
	Scopes []string
	// SkipIssuerCheck skips the openid issuer check
	SkipIssuerCheck bool
}

//Config is used to to complete the Open ID Connect protocol using the Authorization Grant Authentication Flow.
type Config struct {
	oAuth2      *oauth2.Config
	issuer      string
	userInfoUrl string
	skipIssuer  bool
}

type AuthUser struct {
	AuthToken *oauth2.Token
	IDToken   map[string]interface{}
	UserInfo  map[string]interface{}
}

func (u AuthUser) ToUser() *User {
	return &User{
		UserInfo: u.UserInfo,
		IDToken:  u.IDToken,
	}
}

// NewConfig creates a new Config from the given options
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
	if opts.DiscoveryUrl == "" {
		return nil, errors.New("[Config] empty discovery url")
	}
	resp, err := http.Get(opts.DiscoveryUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data := &wellKnown{}
	if err := json.NewDecoder(resp.Body).Decode(data); err != nil {
		return nil, fmt.Errorf("[Config] decoding discovery response: %s", err.Error())
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
		skipIssuer:  opts.SkipIssuerCheck,
	}, nil
}

// OAuth2 returns a pointer to the Configs oauth2.Config
func (c *Config) OAuth2() *oauth2.Config {
	return c.oAuth2
}

func GetSession(r *http.Request) (*sessions.Session, error) {
	return session.Get(r, sessionName)
}

func (c *Config) GetUser(r *http.Request) (*User, error) {
	sess, err := session.Get(r, c.oAuth2.ClientID)
	if err != nil {
		return nil, err
	}
	if data, ok := sess.Values[c.userSessionKey()].(*User); ok {
		return data, nil
	}
	return nil, nil
}

func (c *Config) GetSession(r *http.Request) (*sessions.Session, error) {
	return session.Get(r, c.oAuth2.ClientID)
}

// OAuth2 returns the Configs user info url returned from the discovery endpoint
func (c *Config) UserInfoUrl() string {
	return c.userInfoUrl
}

// OAuth2 returns the Configs issuer returned from the discovery endpoint
func (c *Config) Issuer() string {
	return c.issuer
}

func (c *Config) userSessionKey() string {
	return fmt.Sprintf("%s_user", c.issuer)
}

// getUser gets an OpenID type by exchanging the authorization code for an access & id token, then calling the userinfo endpoint
func (c *Config) getUser(ctx context.Context, code string) (*AuthUser, error) {
	oauth2Token, err := c.oAuth2.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("[Access Token] %s", err.Error())
	}
	client := c.oAuth2.Client(ctx, oauth2Token)
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("[Access Token] missing id_token")
	}
	payload, err := c.parseJWT(rawIDToken)
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

	if !c.skipIssuer {
		if iss, ok := idToken["iss"].(string); ok {
			if iss != c.issuer {
				return nil, fmt.Errorf("[Id Token] issuer mismatch: %s != %s", iss, c.issuer)
			}
		} else {
			return nil, errors.New("[Id Token] missing iss claim")
		}
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
	if usrClaims["sub"] == nil {
		return nil, errors.New("[User Info] missing sub claim")
	}
	if idToken["sub"] != usrClaims["sub"] {
		return nil, fmt.Errorf("[User Info] sub mismatch: %v != %s", idToken["sub"], usrClaims["sub"])
	}
	return &AuthUser{
		UserInfo:  usrClaims,
		IDToken:   idToken,
		AuthToken: oauth2Token,
	}, nil
}

// parseJWT parses the jwt and returns the payload(middle portion)
func (c *Config) parseJWT(p string) ([]byte, error) {
	parts := strings.Split(p, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("malformed jwt, expected 3 parts got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("malformed jwt payload: %v", err)
	}
	return payload, nil
}

//HandleLogin gets the user from the request, executes the LoginHandler and then redirects to the input redirect
func (c *Config) HandleLogin(redirect string, onLogins ...OnLoginFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("code") == "" {
			http.Error(w, "missing authorization code url param", http.StatusBadRequest)
			return
		}
		sess, err := GetSession(r)
		if err != nil {
			http.Error(w, "failed to get session", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("state") != sess.Values["state"].(string) {
			http.Error(w, "invalid state", http.StatusBadRequest)
			return
		}
		//exchange authorization code for a OpenID type containing access token, id token, and userinfo
		usr, err := c.getUser(r.Context(), r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to get user: %s", err.Error()), http.StatusBadRequest)
			return
		}
		if len(onLogins) > 0 {
			for _, handler := range onLogins {
				if err := handler(usr, r); err != nil {
					http.Error(w, fmt.Sprintf("failed to handle user: %s", err.Error()), http.StatusInternalServerError)
					return
				}
			}
		}
		sess.Values["loggedIn"] = true
		if err := sess.Save(r, w); err != nil {
			http.Error(w, "failed to save session", http.StatusBadRequest)
			return
		}
		userSess, err := c.GetSession(r)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to get user session: %s", err.Error()), http.StatusBadRequest)
			return
		}
		userSess.Values[c.userSessionKey()] = usr.ToUser()
		if err := userSess.Save(r, w); err != nil {
			http.Error(w, "failed to save user session", http.StatusBadRequest)
			return
		}
		//redirect to page as authenicated user
		http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
	}
}

//HandleAuthorizationRedirect is an http handler that redirects the user to the identity providers login screen
func (c *Config) HandleAuthorizationRedirect() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := GetSession(r)
		if err != nil {
			http.Error(w, "failed to get session", http.StatusBadRequest)
			return
		}
		state := string(time.Now().UnixNano())
		state = base64.StdEncoding.EncodeToString([]byte(state))
		sess.Values["state"] = state
		if err := sess.Save(r, w); err != nil {
			http.Error(w, "failed to save session", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, c.oAuth2.AuthCodeURL(state), http.StatusTemporaryRedirect)
	}
}

//Logout logs the user out so they cant pass the middleware without authenticating against at least one idp
func Logout(w http.ResponseWriter, r *http.Request) {
	sess, err := GetSession(r)
	if err != nil {
		http.Error(w, "failed to get session", http.StatusBadRequest)
		return
	}
	sess.Values["loggedIn"] = false
	if err := sess.Save(r, w); err != nil {
		http.Error(w, "failed to save session", http.StatusBadRequest)
		return
	}
}

//Middleware wraps the http handler and redirects the user to the redirect if they are not logged in
func Middleware(handler http.HandlerFunc, redirect string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := GetSession(r)
		if err != nil {
			http.Error(w, "failed to get session", http.StatusUnauthorized)
			return
		}
		if sess.Values["loggedIn"] == nil || sess.Values["loggedIn"].(bool) == false {
			http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
			return
		}
		handler.ServeHTTP(w, r)
	}
}
