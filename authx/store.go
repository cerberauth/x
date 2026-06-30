package authx

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/99designs/keyring"
	"golang.org/x/oauth2"
)

type tokenStore interface {
	Save(tok *oauth2.Token, idToken string) error
	Load() (*oauth2.Token, string, error)
	Clear() error
}

type storedToken struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`
	IDToken      string    `json:"id_token,omitempty"`
}

type keyringStore struct {
	service string
	key     string
}

func newKeyringStore(service, key string) *keyringStore {
	return &keyringStore{service: service, key: key}
}

func (s *keyringStore) ring() (keyring.Keyring, error) {
	return keyring.Open(keyring.Config{
		ServiceName: s.service,
	})
}

func (s *keyringStore) Save(t *oauth2.Token, idToken string) error {
	r, err := s.ring()
	if err != nil {
		return err
	}
	b, err := json.Marshal(storedToken{ //nolint:gosec // tokens stored in OS keyring
		AccessToken:  t.AccessToken,
		TokenType:    t.TokenType,
		RefreshToken: t.RefreshToken,
		Expiry:       t.Expiry,
		IDToken:      idToken,
	})
	if err != nil {
		return err
	}
	return r.Set(keyring.Item{Key: s.key, Data: b})
}

func (s *keyringStore) Load() (*oauth2.Token, string, error) {
	r, err := s.ring()
	if err != nil {
		return nil, "", err
	}
	item, err := r.Get(s.key)
	if err != nil {
		if errors.Is(err, keyring.ErrKeyNotFound) {
			return nil, "", ErrNotLoggedIn
		}
		return nil, "", err
	}
	var st storedToken
	if err := json.Unmarshal(item.Data, &st); err != nil {
		return nil, "", err
	}
	tok := &oauth2.Token{
		AccessToken:  st.AccessToken,
		TokenType:    st.TokenType,
		RefreshToken: st.RefreshToken,
		Expiry:       st.Expiry,
	}
	return tok, st.IDToken, nil
}

func (s *keyringStore) Clear() error {
	r, err := s.ring()
	if err != nil {
		return err
	}
	if err := r.Remove(s.key); err != nil && !errors.Is(err, keyring.ErrKeyNotFound) {
		return err
	}
	return nil
}
