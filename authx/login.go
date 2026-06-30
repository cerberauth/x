package authx

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"golang.org/x/oauth2"
)

type authCodeResult struct {
	code string
	err  error
}

func callbackHandler(state string, resCh chan<- authCodeResult) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("state") != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			resCh <- authCodeResult{err: errors.New("state mismatch (possible CSRF)")}
			return
		}
		if e := q.Get("error"); e != "" {
			desc := q.Get("error_description")
			if desc == "" {
				desc = e
			}
			http.Error(w, desc, http.StatusBadRequest)
			resCh <- authCodeResult{err: fmt.Errorf("authorization error: %s", desc)}
			return
		}
		_, _ = io.WriteString(w, "<html><body><p>Login complete. You may close this tab.</p></body></html>")
		resCh <- authCodeResult{code: q.Get("code")}
	}
}

// LoginAuthCode runs the Authorization Code + PKCE flow (RFC 8252). It binds
// an ephemeral loopback port, opens the system browser, and waits for the
// redirect callback. No user interaction beyond the browser is required.
func (a *Authenticator) LoginAuthCode(ctx context.Context) error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	cfg := a.cfg
	cfg.RedirectURL = fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	state, err := randString(32)
	if err != nil {
		return err
	}
	pkce := oauth2.GenerateVerifier()

	resCh := make(chan authCodeResult, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", callbackHandler(state, resCh))

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	authURL := cfg.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.S256ChallengeOption(pkce),
	)
	if err := openBrowser(authURL); err != nil {
		fmt.Printf("Open this URL to log in:\n%s\n", authURL)
	}

	select {
	case res := <-resCh:
		if res.err != nil {
			return res.err
		}
		tok, err := cfg.Exchange(ctx, res.code, oauth2.VerifierOption(pkce))
		if err != nil {
			return err
		}
		return a.verifyAndStore(ctx, tok)
	case <-time.After(3 * time.Minute):
		return errors.New("login timed out after 3 minutes")
	case <-ctx.Done():
		return ctx.Err()
	}
}

// LoginDeviceCode runs the Device Authorization Grant flow (RFC 8628). Use
// this when no browser is available (SSH sessions, CI).
func (a *Authenticator) LoginDeviceCode(ctx context.Context) error {
	var claims struct {
		DeviceAuthURL string `json:"device_authorization_endpoint"`
	}
	if err := a.provider.Claims(&claims); err != nil {
		return fmt.Errorf("could not read discovery claims: %w", err)
	}
	if claims.DeviceAuthURL == "" {
		return errors.New("device_authorization_endpoint not advertised by issuer")
	}

	cfg := a.cfg
	cfg.Endpoint.DeviceAuthURL = claims.DeviceAuthURL

	da, err := cfg.DeviceAuth(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Visit %s and enter code: %s\n", da.VerificationURI, da.UserCode)

	tok, err := cfg.DeviceAccessToken(ctx, da)
	if err != nil {
		return err
	}
	return a.verifyAndStore(ctx, tok)
}

func (a *Authenticator) verifyAndStore(ctx context.Context, tok *oauth2.Token) error {
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return errors.New("no id_token in token response")
	}
	if _, err := a.verifier.Verify(ctx, rawID); err != nil {
		return fmt.Errorf("id token verification failed: %w", err)
	}
	return a.store.Save(tok, rawID)
}

func randString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func openBrowser(url string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd, args = "open", []string{url}
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		cmd, args = "xdg-open", []string{url}
	}
	return exec.Command(cmd, args...).Start()
}
