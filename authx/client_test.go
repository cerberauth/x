package authx

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

type mockTokenSource struct {
	tok *oauth2.Token
	err error
}

func (m *mockTokenSource) Token() (*oauth2.Token, error) { return m.tok, m.err }

func TestStatus_notLoggedIn(t *testing.T) {
	a := newTestAuthenticator(&memStore{empty: true})
	_, err := a.Status(context.Background())
	require.ErrorIs(t, err, ErrNotLoggedIn)
}

func TestStatus_loggedIn(t *testing.T) {
	expiry := time.Now().Add(time.Hour).Truncate(time.Second)
	store := &memStore{tok: &oauth2.Token{AccessToken: "tok", Expiry: expiry}, idToken: "id.tok.sig"}
	a := newTestAuthenticator(store)

	info, err := a.Status(context.Background())
	require.NoError(t, err)
	assert.Equal(t, expiry, info.Expiry)
	assert.Equal(t, "id.tok.sig", info.IDToken)
}

func TestLogout_clearsStore(t *testing.T) {
	store := &memStore{tok: &oauth2.Token{AccessToken: "tok"}, idToken: "id"}
	a := newTestAuthenticator(store)

	require.NoError(t, a.Logout(context.Background()))

	_, err := a.Status(context.Background())
	require.ErrorIs(t, err, ErrNotLoggedIn)
}

func TestClient_notLoggedIn(t *testing.T) {
	a := newTestAuthenticator(&memStore{empty: true})
	_, err := a.Client(context.Background())
	require.ErrorIs(t, err, ErrNotLoggedIn)
}

func TestPersistingSource_persistsRefresh(t *testing.T) {
	store := &memStore{}
	original := &oauth2.Token{AccessToken: "old", RefreshToken: "rt", Expiry: time.Now().Add(time.Hour)}
	refreshed := &oauth2.Token{AccessToken: "new", RefreshToken: "rt2", Expiry: time.Now().Add(2 * time.Hour)}

	ps := &persistingSource{
		base:    &mockTokenSource{tok: refreshed},
		store:   store,
		last:    original.AccessToken,
		idToken: "original-id",
	}

	tok, err := ps.Token()
	require.NoError(t, err)
	assert.Equal(t, "new", tok.AccessToken)
	assert.Equal(t, "new", store.tok.AccessToken)
	assert.Equal(t, "original-id", store.idToken, "carries forward stored id_token when refresh omits it")
}

func TestPersistingSource_noSaveWhenUnchanged(t *testing.T) {
	store := &memStore{saveErr: errors.New("should not save")}
	tok := &oauth2.Token{AccessToken: "same", Expiry: time.Now().Add(time.Hour)}

	ps := &persistingSource{
		base:  &mockTokenSource{tok: tok},
		store: store,
		last:  "same",
	}

	_, err := ps.Token()
	require.NoError(t, err) // save not called, so saveErr not triggered
}

func TestPersistingSource_propagatesSourceError(t *testing.T) {
	want := errors.New("refresh failed")
	ps := &persistingSource{
		base:  &mockTokenSource{err: want},
		store: &memStore{},
		last:  "tok",
	}

	_, err := ps.Token()
	require.ErrorIs(t, err, want)
}

func TestPersistingSource_usesNewIDTokenWhenPresent(t *testing.T) {
	store := &memStore{}
	refreshed := &oauth2.Token{AccessToken: "new"}
	refreshed = refreshed.WithExtra(map[string]interface{}{"id_token": "new-id"})

	ps := &persistingSource{
		base:    &mockTokenSource{tok: refreshed},
		store:   store,
		last:    "old",
		idToken: "old-id",
	}

	_, err := ps.Token()
	require.NoError(t, err)
	assert.Equal(t, "new-id", store.idToken)
}
