// Package forwarder POSTs Lemma signed-evidence envelopes to a Control
// Plane URL. One JSONL line per request, Content-Type application/json,
// 2xx counted as success and anything else as failure. Stateless — the
// caller manages chain bookkeeping and which envelopes to send.
//
// Federation arc on #25. Slice L (#196) shipped the HTTP path; this
// extension adds mTLS so the agent can authenticate to a Control Plane
// via client certificates and pin the server certificate via a CA
// bundle. Retry/backoff, resumable bookmarks, and bulk POSTs are still
// out of scope; operators wrap this with shell tooling for now.
package forwarder

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Options threads optional inputs through Forward.
type Options struct {
	// Headers added to every request (e.g. "Authorization: Bearer ...").
	// Content-Type is set automatically and cannot be overridden.
	Headers map[string]string

	// Timeout per request. Zero means use the http.Client default.
	Timeout time.Duration

	// MTLSCertPath / MTLSKeyPath are the client certificate + private
	// key files (PEM). Both must be set together; setting only one is
	// a usage error. When set, the URL must be https://.
	MTLSCertPath string
	MTLSKeyPath  string

	// MTLSCAPath is the CA bundle PEM used to verify the server
	// certificate. When unset and the URL is https://, Go's stdlib
	// system trust store is used. When set, replaces the system pool.
	MTLSCAPath string

	// InsecureSkipVerify skips server certificate verification.
	// Dev/test escape hatch only — emits a stderr warning at the CLI
	// layer; here we just honour the flag.
	InsecureSkipVerify bool
}

// Result is the per-call outcome.
type Result struct {
	// Forwarded is the count of envelopes for which the server returned
	// a 2xx status code.
	Forwarded int
	// Failed is the count of envelopes for which the request errored or
	// the server returned a non-2xx status code.
	Failed int
}

// Forward reads jsonlPath line-by-line and POSTs each non-blank line as
// a JSON document to url. Errors are returned only for setup-time
// failures (e.g. file not found, malformed mTLS material); per-request
// failures are surfaced via Result.Failed.
func Forward(jsonlPath, url string, opts Options) (Result, error) {
	if err := validateMTLSOptions(url, opts); err != nil {
		return Result{}, err
	}

	tlsCfg, err := buildTLSConfig(opts)
	if err != nil {
		return Result{}, err
	}

	f, err := os.Open(jsonlPath)
	if err != nil {
		return Result{}, fmt.Errorf("forwarder: open %s: %w", jsonlPath, err)
	}
	defer f.Close()

	transport := &http.Transport{TLSClientConfig: tlsCfg}
	client := &http.Client{Timeout: opts.Timeout, Transport: transport}

	var res Result
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // OCSF events can be large
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(strings.TrimSpace(string(raw))) == 0 {
			continue
		}
		// Copy bytes — bufio.Scanner reuses its buffer between Scan calls.
		body := make([]byte, len(raw))
		copy(body, raw)

		ok := postOne(client, url, body, opts.Headers)
		if ok {
			res.Forwarded++
		} else {
			res.Failed++
		}
	}
	if err := scanner.Err(); err != nil {
		return res, fmt.Errorf("forwarder: scan: %w", err)
	}
	return res, nil
}

// postOne issues a single POST. Returns true on a 2xx response, false
// on any other status code or transport error. The response body is
// drained and discarded so connection reuse stays clean.
func postOne(client *http.Client, url string, body []byte, headers map[string]string) bool {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		// Caller-supplied headers can't override Content-Type.
		if strings.EqualFold(k, "Content-Type") {
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// validateMTLSOptions enforces three rules on the option set up front so
// invalid combinations don't silently fall back to plain TLS:
//
//   - --mtls-cert and --mtls-key must be set together.
//   - mTLS flags (cert/key/ca/insecure-skip-verify) require an https://
//     URL — otherwise the operator is asking for security guarantees
//     that the protocol can't deliver.
func validateMTLSOptions(url string, opts Options) error {
	hasCert := opts.MTLSCertPath != ""
	hasKey := opts.MTLSKeyPath != ""
	if hasCert != hasKey {
		return errors.New("forwarder: --mtls-cert and --mtls-key must be set together")
	}
	usesMTLS := hasCert || opts.MTLSCAPath != "" || opts.InsecureSkipVerify
	if usesMTLS && !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("forwarder: mTLS flags require an https:// URL, got %q", url)
	}
	return nil
}

// buildTLSConfig assembles a *tls.Config from opts, or returns nil when
// no TLS-related options are set (in which case http.Transport falls
// back to its defaults — fine for HTTP and for HTTPS against the system
// trust store with no client cert).
func buildTLSConfig(opts Options) (*tls.Config, error) {
	if opts.MTLSCertPath == "" && opts.MTLSCAPath == "" && !opts.InsecureSkipVerify {
		return nil, nil
	}
	cfg := &tls.Config{
		InsecureSkipVerify: opts.InsecureSkipVerify, //nolint:gosec // operator opt-in
	}
	if opts.MTLSCertPath != "" {
		pair, err := tls.LoadX509KeyPair(opts.MTLSCertPath, opts.MTLSKeyPath)
		if err != nil {
			return nil, fmt.Errorf("forwarder: load client cert+key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	if opts.MTLSCAPath != "" {
		pem, err := os.ReadFile(opts.MTLSCAPath)
		if err != nil {
			return nil, fmt.Errorf("forwarder: read CA bundle %s: %w", opts.MTLSCAPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("forwarder: no certificates parsed from CA bundle %s", opts.MTLSCAPath)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}
