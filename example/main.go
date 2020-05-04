package main

import (
	"github.com/ShaleApps/openid"
	"log"
	"net/http"
	"os"
)

func main() {
	config, err := openid.NewConfig(&openid.Opts{
		DiscoveryUrl:    os.Getenv("OPENID_TEST_DISCOVERY_URL"), // ex: https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration
		ClientID:        os.Getenv("OPENID_TEST_CLIENT_ID"),
		ClientSecret:    os.Getenv("OPENID_TEST_CLIENT_SECRET"), //do not commit to code
		Redirect:        os.Getenv("OPENID_TEST_REDIRECT"),      //localhost:8080/login
		Scopes:          openid.DefaultScopes,
		SkipIssuerCheck: true,
	})
	if err != nil {
		log.Fatal(err.Error())
	}
	const (
		home          = "/home"                //this is a protected route that cannot be accessed unless they have logged in
		login         = "/login"               //this is where the identity provider will redirect the user to after they login
		authorization = "/login/authorization" //redirects the user to login to the identity provider
	)
	mux := http.NewServeMux()
	mux.HandleFunc(authorization, config.HandleAuthorizationRedirect())
	//protected, will redirect to authorization if not logged in.
	mux.HandleFunc(home, openid.Middleware(func(w http.ResponseWriter, r *http.Request) {
		usr, err := config.GetUser(r)
		if err != nil {
			http.Error(w, "failed to get user", http.StatusInternalServerError)
			return
		}
		w.Write([]byte(usr.String()))
	}, authorization))
	//this is the oauth2 callback that will redirect to home after login
	mux.HandleFunc(login, config.HandleLogin(home))
	http.ListenAndServe(":8080", mux)
}
