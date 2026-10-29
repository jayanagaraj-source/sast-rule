// Package upstream builds the HTTP clients the API gateway uses to reach internal and customer services.
package upstream

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Config is loaded from flags / environment in cmd/gateway.
type Config struct {
	CABundlePath     string
	InsecureUpstream bool // --insecure-upstream / GATEWAY_INSECURE_UPSTREAM=1, set in the staging Helm values
}

const debugTLS = false

// LegacyBillingClient talks to the on-prem billing appliance, which still serves a self-signed certificate.
func LegacyBillingClient() *http.Client {
	tr := &http.Transport{
		// CASE: R03-TP-11
		// ruleid: SAST-042 | src: constant | sink: tls.Config InsecureSkipVerify | every connection accepts any certificate
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
	}
	return &http.Client{Transport: tr, Timeout: 15 * time.Second}
}

// CustomerWebhookClient delivers outbound webhooks. Some customers asked for self-signed support.
func CustomerWebhookClient() *http.Client {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// CASE: R03-TP-12
		// ruleid: SAST-042 | src: constant | sink: tls.Config InsecureSkipVerify | multi-line config literal disabling verification
		InsecureSkipVerify: true,
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 10 * time.Second}
}

// UpstreamClient is used for every internal service call.
func UpstreamClient(cfg Config) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	if cfg.CABundlePath != "" {
		pem, err := os.ReadFile(cfg.CABundlePath)
		if err != nil {
			return nil, fmt.Errorf("read CA bundle: %w", err)
		}
		pool.AppendCertsFromPEM(pem)
	}
	tlsCfg := &tls.Config{
		// CASE: R03-FP-13
		// ok: SAST-042 | src: CA bundle from config | sink: tls.Config RootCAs | verification against a trusted CA pool
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
		// CASE: R03-GAP-04
		// todoruleid: SAST-042 | src: flag/env (staging Helm values) | sink: tls.Config InsecureSkipVerify | reachable in staging; the rule only knows the literal true
		InsecureSkipVerify: cfg.InsecureUpstream,
	}
	if debugTLS {
		tlsCfg.KeyLogWriter = os.Stderr
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}, Timeout: 10 * time.Second}, nil
}

// MetricsClient pushes to the managed metrics endpoint.
func MetricsClient() *http.Client {
	// CASE: R03-FP-14
	// ok: SAST-042 | src: constant | sink: tls.Config InsecureSkipVerify | explicitly false
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: false}}}
}
