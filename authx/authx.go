package authx

import (
	"context"
	"errors"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// DefaultIssuer is the hardcoded cerberauth authorization server.
const DefaultIssuer = "https://oauth.cerberauth.com"

// ErrNotLoggedIn is returned when no valid credential exists in the store.
var ErrNotLoggedIn = errors.New("not logged in: run `auth login`")

// oidcNewProvider is a seam for testing.
var oidcNewProvider = oidc.NewProvider

// Authenticator manages OIDC/OAuth2 credentials for a CLI tool.
type Authenticator struct {
	provider *oidc.Provider
	cfg      oauth2.Config
	verifier *oidc.IDTokenVerifier
	store    tokenStore
}

type options struct {
	issuer         string
	scopes         []string
	keyringService string
}

// Option configures New.
type Option func(*options)

// WithIssuer overrides the OIDC issuer URL (default: DefaultIssuer).
func WithIssuer(issuer string) Option {
	return func(o *options) { o.issuer = issuer }
}

// WithScopes sets the OAuth2 scopes requested during login.
// Default: openid, profile, email, offline_access.
func WithScopes(scopes ...string) Option {
	return func(o *options) { o.scopes = scopes }
}

// WithKeyringService overrides the OS keyring service name (default: "cerberauth").
func WithKeyringService(service string) Option {
	return func(o *options) { o.keyringService = service }
}

// New performs OIDC discovery and returns an Authenticator. clientID is the
// OAuth2 public client ID registered with the authorization server.
func New(ctx context.Context, clientID string, opts ...Option) (*Authenticator, error) {
	o := &options{
		issuer:         DefaultIssuer,
		scopes:         []string{oidc.ScopeOpenID, "profile", "email", oidc.ScopeOfflineAccess},
		keyringService: "cerberauth",
	}
	for _, opt := range opts {
		opt(o)
	}

	provider, err := oidcNewProvider(ctx, o.issuer)
	if err != nil {
		return nil, err
	}

	return &Authenticator{
		provider: provider,
		cfg: oauth2.Config{
			ClientID: clientID,
			Endpoint: provider.Endpoint(),
			Scopes:   o.scopes,
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: clientID}),
		store:    newKeyringStore(o.keyringService, o.issuer+"|"+clientID),
	}, nil
}
