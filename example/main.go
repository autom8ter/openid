package main

import (
	"github.com/ShaleApps/openid"
	"log"
	"net/http"
	"os"
)

func main() {
	config, err := openid.NewConfig(&openid.Opts{
		DiscoveryUrl:    os.Getenv("OPENID_TEST_DISCOVERY_URL"),
		ClientID:        os.Getenv("OPENID_TEST_CLIENT_ID"),
		ClientSecret:    os.Getenv("OPENID_TEST_CLIENT_SECRET"),
		Redirect:        os.Getenv("OPENID_TEST_REDIRECT"),
		Scopes:          openid.DefaultScopes,
		SkipIssuerCheck: true,
	})
	if err != nil {
		log.Fatal(err.Error())
	}
	const (
		home = "/home"
		login = "/login"
		authorization = "/login/authorization"
	)
	mux := http.NewServeMux()
	///login/authorization redirects the user to login to the identity provider
	mux.HandleFunc(authorization, config.HandleAuthorizationRedirect())
	///mock home
	mux.HandleFunc(home, openid.Middleware(func(w http.ResponseWriter, r *http.Request) {
		usr, err := config.GetUser(r)
		if err != nil {
			http.Error(w, "failed to get user", http.StatusInternalServerError)
			return
		}
		w.Write([]byte(usr.String()))
	}, authorization))
	//mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	//	w.Write([]byte("hello!"))
	//})
	mux.HandleFunc(login, config.HandleLogin(home))
	http.ListenAndServe(":8080", mux)
}
