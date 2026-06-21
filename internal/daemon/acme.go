package daemon

import (
	"context"
	"crypto/tls"
	"net/http"
	"path/filepath"
	"time"

	"log/slog"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// buildUITLSConfig returns a *tls.Config for the UI server when ACME is enabled,
// plus an HTTP-01 challenge handler that must be served on :80. It serves
// autocert-issued certs from the configured directory (step-ca or Let's Encrypt)
// and falls back to the internal-PKI host cert while issuance is pending or for a
// ServerName outside the domain allowlist — so the UI always presents SOME cert.
// Returns (nil, nil) when ACME is disabled (UI stays plain HTTP).
func (d *Daemon) buildUITLSConfig() (*tls.Config, http.Handler) {
	if !d.cfg.ACME.Enabled() {
		return nil, nil
	}
	cacheDir := d.cfg.ACME.CacheDir
	if cacheDir == "" {
		cacheDir = filepath.Join(d.cfg.DataDir, "acme")
	}
	mgr := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cacheDir),
		HostPolicy: autocert.HostWhitelist(d.cfg.ACME.Domains...),
		Email:      d.cfg.ACME.Email,
		Client:     &acme.Client{DirectoryURL: d.cfg.ACME.DirectoryURL},
	}

	// Load the internal-PKI host cert once for the fallback path.
	fallback, ferr := tls.LoadX509KeyPair(
		filepath.Join(d.cfg.PKIDir, "host.crt"),
		filepath.Join(d.cfg.PKIDir, "host.key"),
	)
	haveFallback := ferr == nil
	if !haveFallback {
		slog.Warn("acme: internal-PKI fallback cert unavailable", "error", ferr)
	}

	getCert := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := mgr.GetCertificate(hello)
		if err == nil {
			return cert, nil
		}
		if haveFallback {
			slog.Warn("acme: serving internal-PKI fallback cert", "server_name", hello.ServerName, "error", err)
			return &fallback, nil
		}
		return nil, err
	}

	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: getCert,
		NextProtos:     []string{"h2", "http/1.1", acme.ALPNProto},
	}
	slog.Info("acme: UI TLS enabled", "directory", d.cfg.ACME.DirectoryURL, "domains", d.cfg.ACME.Domains, "cache", cacheDir)
	return tlsCfg, mgr.HTTPHandler(nil)
}

// startACMEChallengeServer serves the autocert HTTP-01 challenge on :80. autocert
// only answers /.well-known/acme-challenge/… there; its default handler 302s
// everything else to https, which is fine. Best-effort: a bind failure (port in
// use) is logged, not fatal — issuance just can't complete via HTTP-01 then.
func startACMEChallengeServer(ctx context.Context, h http.Handler) {
	if h == nil {
		return
	}
	srv := &http.Server{Addr: ":80", Handler: h, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Warn("acme: HTTP-01 challenge server stopped", "error", err)
		}
	}()
}
