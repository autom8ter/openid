# openid
--
    import "github.com/autom8ter/openid"


## Usage

```go
var (
	//DefaultScopes are added if a Configs scopes are empty, they include: openid, email, profile
	DefaultScopes = []string{"openid", "email", "profile"}
)
```

#### type Config

```go
type Config struct {
}
```

Config is used to to complete the Open ID Connect protocol using the
Authorization Grant Authentication Flow.

#### func  NewConfig

```go
func NewConfig(opts *Opts) (*Config, error)
```
NewConfig creates a new Config from the given options

#### func (*Config) GetOpenID

```go
func (c *Config) GetOpenID(ctx context.Context, code string) (*OpenID, error)
```
GetOpenID gets an OpenID type by exchanging the authorization code for an access
& id token, then calling the userinfo endpoint

#### func (*Config) Issuer

```go
func (c *Config) Issuer() string
```
OAuth2 returns the Configs issuer returned from the discovery endpoint

#### func (*Config) OAuth2

```go
func (c *Config) OAuth2() *oauth2.Config
```
OAuth2 returns a pointer to the Configs oauth2.Config

#### func (*Config) ParseJWT

```go
func (c *Config) ParseJWT(p string) ([]byte, error)
```
ParseJWT parses the jwt and returns the payload(middle portion)

#### func (*Config) UserInfoUrl

```go
func (c *Config) UserInfoUrl() string
```
OAuth2 returns the Configs user info url returned from the discovery endpoint

#### type OpenID

```go
type OpenID struct {
	AuthToken *oauth2.Token
	IDToken   map[string]interface{}
	UserInfo  map[string]interface{}
}
```

OpenID contains the Access Token returned from the token endpoint, the ID tokens
payload, and the payload returned from the userInfo endpoint

#### func (*OpenID) String

```go
func (o *OpenID) String() string
```
String prints a pretty json string of the OpenID

#### type Opts

```go
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
```

Opts are options used when creating a new Configuration
