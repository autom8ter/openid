package openid_test

import (
	"context"
	"github.com/ShaleApps/openid"
	"os"
	"testing"
)

//https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration
func Test(t *testing.T) {
	config, err := openid.NewConfig(&openid.Opts{
		DiscoveryUrl:    os.Getenv("OPENID_TEST_DISCOVERY_URL"),
		ClientID:        os.Getenv("OPENID_TEST_CLIENT_ID"),
		ClientSecret:    os.Getenv("OPENID_TEST_CLIENT_SECRET"),
		Redirect:        os.Getenv("OPENID_TEST_REDIRECT"),
		Scopes:          openid.DefaultScopes,
		SkipIssuerCheck: true,
	})
	if err != nil {
		t.Fatal(err.Error())
	}
	id, err := config.GetUser(context.Background(), os.Getenv("OPENID_TEST_CODE"))
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Log(id.String())
}
