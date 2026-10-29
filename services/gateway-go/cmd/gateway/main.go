package main

import (
	"encoding/json"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/caseflow-example/gateway/internal/upstream"
)

const statusURL = "https://status.partner-crm.example/api/v2/status.json"

func main() {
	insecure := flag.Bool("insecure-upstream", os.Getenv("GATEWAY_INSECURE_UPSTREAM") == "1", "skip TLS verification for upstreams (staging only)")
	caBundle := flag.String("ca-bundle", "/etc/ssl/certs/internal-ca.pem", "extra CA bundle for internal services")
	staticDir := flag.String("static", "/srv/gateway/static", "static asset directory")
	flag.Parse()

	client, err := upstream.UpstreamClient(upstream.Config{CABundlePath: *caBundle, InsecureUpstream: *insecure})
	if err != nil {
		slog.Error("upstream client", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /partner-status", func(w http.ResponseWriter, r *http.Request) {
		// CASE: R04-FP-12
		// ok: TG-TAINT-JS-SSRF | src: constant URL | sink: http.Client.Get | fixed host in Go; JS-only taint rule must stay silent
		resp, err := client.Get(statusURL)
		if err != nil {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		_ = json.NewEncoder(w).Encode(body)
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		// CASE: R13-FP-15, R10-FP-26
		// ok: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal, gitlab.eslint.detect-non-literal-fs-filename | src: constant filename | sink: filepath.Join + ServeFile | Go path join of a fixed file; JS-only rules must stay silent
		http.ServeFile(w, r, filepath.Join(*staticDir, "index.html"))
	})

	slog.Info("gateway listening", "addr", ":8443")
	if err := http.ListenAndServeTLS(":8443", "/etc/gateway/tls.crt", "/etc/gateway/tls.key", mux); err != nil {
		slog.Error("server stopped", "err", err)
	}
}
