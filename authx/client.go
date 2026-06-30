package authx

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// TokenInfo holds metadata about the currently stored credential.
type TokenInfo struct {
	Expiry  time.Time
	IDToken string
}

// Client returns an *http.Client whose transport auto-refreshes the access
// token using the stored refresh token, persisting each refresh back to the
// OS keyring. Returns ErrNotLoggedIn if no credential is stored.
func (a *Authenticator) Client(ctx context.Context) (*http.Client, error) {
	tok, idToken, err := a.store.Load()
	if err != nil {
		return nil, err
	}
	ts := &persistingSource{
		base:    a.cfg.TokenSource(ctx, tok),
		store:   a.store,
		last:    tok.AccessToken,
		idToken: idToken,
	}
	return oauth2.NewClient(ctx, ts), nil
}

// Token returns the current access token string, refreshing via the stored
// refresh token if necessary. The refreshed token is persisted back to the
// OS keyring. Returns ErrNotLoggedIn if no credential is stored.
func (a *Authenticator) Token(ctx context.Context) (string, error) {
	tok, idToken, err := a.store.Load()
	if err != nil {
		return "", err
	}
	ts := &persistingSource{
		base:    a.cfg.TokenSource(ctx, tok),
		store:   a.store,
		last:    tok.AccessToken,
		idToken: idToken,
	}
	refreshed, err := ts.Token()
	if err != nil {
		return "", err
	}
	return refreshed.AccessToken, nil
}

// Status returns token metadata. Returns ErrNotLoggedIn if no credential is stored.
func (a *Authenticator) Status(ctx context.Context) (*TokenInfo, error) {
	tok, idToken, err := a.store.Load()
	if err != nil {
		return nil, err
	}
	return &TokenInfo{
		Expiry:  tok.Expiry,
		IDToken: idToken,
	}, nil
}

// Logout clears stored credentials from the OS keyring.
func (a *Authenticator) Logout(ctx context.Context) error {
	return a.store.Clear()
}

// persistingSource wraps an oauth2.TokenSource and writes each refreshed
// token back to the store so the user does not need to re-login after expiry.
type persistingSource struct {
	base    oauth2.TokenSource
	store   tokenStore
	last    string
	idToken string // last known id_token; carried forward when refresh omits it
}

func (p *persistingSource) Token() (*oauth2.Token, error) {
	tok, err := p.base.Token()
	if err != nil {
		return nil, err
	}
	if tok.AccessToken != p.last {
		rawID, _ := tok.Extra("id_token").(string)
		if rawID == "" {
			rawID = p.idToken
		}
		_ = p.store.Save(tok, rawID)
		p.last = tok.AccessToken
		p.idToken = rawID
	}
	return tok, nil
}
