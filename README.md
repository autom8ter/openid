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

#### func  GetSession

```go
func GetSession(r *http.Request) (*sessions.Session, error)
```

#### func  Middleware

```go
func Middleware(handler http.HandlerFunc, redirect string) http.HandlerFunc
```
Middleware wraps the http handler and redirects the user to the redirect if they
are not logged in

#### func  SetSession

```go
func SetSession(store *sessions.CookieStore)
```
SetSession overrides the default session store(recommended for production usage)

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

#### func (*Config) GetUser

```go
func (c *Config) GetUser(r *http.Request) (*User, error)
```

#### func (*Config) HandleAuthorizationRedirect

```go
func (c *Config) HandleAuthorizationRedirect() http.HandlerFunc
```
HandleAuthorizationRedirect is an http handler that redirects the user to the
identity providers login screen

#### func (*Config) HandleLogin

```go
func (c *Config) HandleLogin(redirect string) http.HandlerFunc
```
HandleLogin gets the user from the request, executes the LoginHandler and then
redirects to the input redirect

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

#### func (*Config) UserInfoUrl

```go
func (c *Config) UserInfoUrl() string
```
OAuth2 returns the Configs user info url returned from the discovery endpoint

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

#### type User

```go
type User struct {
	IDToken  map[string]interface{} `json:"id_token"`
	UserInfo map[string]interface{} `json:"user_info"`
}
```

User is a combination of the IDToken and the data returned from the UserInfo
endpoint

#### func (*User) String

```go
func (o *User) String() string
```
