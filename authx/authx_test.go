package authx

import (
	"context"
	"errors"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// memStore is an in-memory tokenStore for unit tests.
type memStore struct {
	tok     *oauth2.Token
	idToken string
	empty   bool
	saveErr error
}

func (m *memStore) Save(tok *oauth2.Token, idToken string) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.tok, m.idToken, m.empty = tok, idToken, false
	return nil
}

func (m *memStore) Load() (*oauth2.Token, string, error) {
	if m.empty || m.tok == nil {
		return nil, "", ErrNotLoggedIn
	}
	return m.tok, m.idToken, nil
}

func (m *memStore) Clear() error {
	m.tok, m.idToken, m.empty = nil, "", true
	return nil
}

func newTestAuthenticator(store tokenStore) *Authenticator {
	return &Authenticator{
		provider: nil,
		cfg: oauth2.Config{
			ClientID: "test-client",
			Endpoint: oauth2.Endpoint{
				TokenURL: "http://localhost/token",
			},
			Scopes: []string{oidc.ScopeOpenID},
		},
		store: store,
	}
}

func TestNew_propagatesDiscoveryError(t *testing.T) {
	orig := oidcNewProvider
	t.Cleanup(func() { oidcNewProvider = orig })

	want := errors.New("discovery failed")
	oidcNewProvider = func(_ context.Context, _ string) (*oidc.Provider, error) {
		return nil, want
	}

	_, err := New(context.Background(), "client-id")
	require.ErrorIs(t, err, want)
}

func TestRandString_length(t *testing.T) {
	s, err := randString(32)
	require.NoError(t, err)
	assert.NotEmpty(t, s)
	// base64url without padding: ceil(32*8/6) = 43 chars
	assert.Equal(t, 43, len(s))
}

func TestRandString_uniqueness(t *testing.T) {
	a, _ := randString(16)
	b, _ := randString(16)
	assert.NotEqual(t, a, b)
}
