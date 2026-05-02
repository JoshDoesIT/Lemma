package forwarder

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// makeJSONLFile writes a temp .jsonl file with the given lines and
// returns its path.
func makeJSONLFile(t *testing.T, lines []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "envelopes.jsonl")
	body := strings.Join(lines, "\n")
	if len(lines) > 0 {
		body += "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// recordingServer captures every received POST so tests can assert.
type recordingServer struct {
	mu       sync.Mutex
	bodies   [][]byte
	headers  []http.Header
	respCode int
}

func newRecordingServer(respCode int) *recordingServer {
	return &recordingServer{respCode: respCode}
}

func (s *recordingServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		defer r.Body.Close()
		s.mu.Lock()
		s.bodies = append(s.bodies, body)
		// Clone the headers so the underlying map can be reused safely.
		hdr := http.Header{}
		for k, v := range r.Header {
			hdr[k] = append([]string{}, v...)
		}
		s.headers = append(s.headers, hdr)
		code := s.respCode
		s.mu.Unlock()
		w.WriteHeader(code)
	}
}

func (s *recordingServer) snapshot() ([][]byte, []http.Header) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bodies, s.headers
}

func TestForwardPOSTsEachEnvelopeOnce(t *testing.T) {
	rs := newRecordingServer(200)
	srv := httptest.NewServer(rs.handler())
	defer srv.Close()

	jsonl := makeJSONLFile(t, []string{
		`{"entry_hash":"a"}`,
		`{"entry_hash":"b"}`,
		`{"entry_hash":"c"}`,
	})
	res, err := Forward(jsonl, srv.URL, Options{})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if res.Forwarded != 3 {
		t.Errorf("forwarded = %d, want 3", res.Forwarded)
	}
	if res.Failed != 0 {
		t.Errorf("failed = %d, want 0", res.Failed)
	}

	bodies, _ := rs.snapshot()
	if len(bodies) != 3 {
		t.Fatalf("server received %d POSTs, want 3", len(bodies))
	}
	wantBodies := []string{
		`{"entry_hash":"a"}`,
		`{"entry_hash":"b"}`,
		`{"entry_hash":"c"}`,
	}
	for i, want := range wantBodies {
		if string(bodies[i]) != want {
			t.Errorf("POST %d body = %q, want %q", i, bodies[i], want)
		}
	}
}

func TestForwardSetsContentTypeJSON(t *testing.T) {
	rs := newRecordingServer(200)
	srv := httptest.NewServer(rs.handler())
	defer srv.Close()

	jsonl := makeJSONLFile(t, []string{`{"entry_hash":"a"}`})
	if _, err := Forward(jsonl, srv.URL, Options{}); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	_, headers := rs.snapshot()
	if got := headers[0].Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
}

func TestForwardPropagatesCustomHeaders(t *testing.T) {
	rs := newRecordingServer(200)
	srv := httptest.NewServer(rs.handler())
	defer srv.Close()

	jsonl := makeJSONLFile(t, []string{`{"entry_hash":"a"}`})
	opts := Options{
		Headers: map[string]string{
			"X-Lemma-Producer":     "Lemma",
			"Authorization":        "Bearer token-xyz",
			"X-Custom-Trace-Id":    "trace-123",
		},
	}
	if _, err := Forward(jsonl, srv.URL, opts); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	_, headers := rs.snapshot()
	for k, want := range opts.Headers {
		if got := headers[0].Get(k); got != want {
			t.Errorf("header %s = %q, want %q", k, got, want)
		}
	}
}

func TestForwardCounts5xxAsFailure(t *testing.T) {
	rs := newRecordingServer(500)
	srv := httptest.NewServer(rs.handler())
	defer srv.Close()

	jsonl := makeJSONLFile(t, []string{`{"entry_hash":"a"}`, `{"entry_hash":"b"}`})
	res, err := Forward(jsonl, srv.URL, Options{})
	if err != nil {
		t.Fatalf("Forward returned error (should report via Result): %v", err)
	}
	if res.Forwarded != 0 {
		t.Errorf("forwarded = %d, want 0", res.Forwarded)
	}
	if res.Failed != 2 {
		t.Errorf("failed = %d, want 2", res.Failed)
	}
}

func TestForwardCounts4xxAsFailure(t *testing.T) {
	rs := newRecordingServer(401)
	srv := httptest.NewServer(rs.handler())
	defer srv.Close()

	jsonl := makeJSONLFile(t, []string{`{"entry_hash":"a"}`})
	res, _ := Forward(jsonl, srv.URL, Options{})
	if res.Failed != 1 {
		t.Errorf("4xx should count as failure; failed=%d", res.Failed)
	}
}

func TestForwardMixedStatusCodesCount2xxOnlyAsForwarded(t *testing.T) {
	// First two requests succeed, third fails.
	var counter int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		counter++
		c := counter
		mu.Unlock()
		if c == 3 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(202)
	}))
	defer srv.Close()

	jsonl := makeJSONLFile(t, []string{
		`{"entry_hash":"a"}`,
		`{"entry_hash":"b"}`,
		`{"entry_hash":"c"}`,
	})
	res, _ := Forward(jsonl, srv.URL, Options{})
	if res.Forwarded != 2 {
		t.Errorf("forwarded = %d, want 2", res.Forwarded)
	}
	if res.Failed != 1 {
		t.Errorf("failed = %d, want 1", res.Failed)
	}
}

func TestForwardSkipsBlankLines(t *testing.T) {
	rs := newRecordingServer(200)
	srv := httptest.NewServer(rs.handler())
	defer srv.Close()

	jsonl := filepath.Join(t.TempDir(), "with-blanks.jsonl")
	body := `{"entry_hash":"a"}` + "\n\n" + `{"entry_hash":"b"}` + "\n   \n"
	if err := os.WriteFile(jsonl, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Forward(jsonl, srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Forwarded != 2 {
		t.Errorf("forwarded = %d, want 2 (blanks ignored)", res.Forwarded)
	}
}

func TestForwardEmptyFileIsZeroForwardedNotError(t *testing.T) {
	rs := newRecordingServer(200)
	srv := httptest.NewServer(rs.handler())
	defer srv.Close()

	jsonl := filepath.Join(t.TempDir(), "empty.jsonl")
	if err := os.WriteFile(jsonl, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Forward(jsonl, srv.URL, Options{})
	if err != nil {
		t.Fatalf("empty file should not error, got %v", err)
	}
	if res.Forwarded != 0 || res.Failed != 0 {
		t.Errorf("empty file: forwarded=%d failed=%d, want 0/0",
			res.Forwarded, res.Failed)
	}
}

func TestForwardErrorsForMissingFile(t *testing.T) {
	if _, err := Forward("/nonexistent/x.jsonl", "http://localhost", Options{}); err == nil {
		t.Error("expected error on missing file, got nil")
	}
}

func TestForwardCountsUnreachableServerAsFailure(t *testing.T) {
	jsonl := makeJSONLFile(t, []string{`{"entry_hash":"a"}`, `{"entry_hash":"b"}`})
	// Use a port that nothing is listening on. Short timeout so the test
	// doesn't wait for the OS default.
	res, _ := Forward(jsonl, "http://127.0.0.1:1", Options{
		Timeout: 500 * time.Millisecond,
	})
	if res.Failed != 2 {
		t.Errorf("unreachable server should count as failure; failed=%d", res.Failed)
	}
}

func TestForwardPreservesEnvelopeOrderInPOSTBodies(t *testing.T) {
	rs := newRecordingServer(200)
	srv := httptest.NewServer(rs.handler())
	defer srv.Close()

	lines := []string{
		`{"entry_hash":"first"}`,
		`{"entry_hash":"second"}`,
		`{"entry_hash":"third"}`,
		`{"entry_hash":"fourth"}`,
	}
	if _, err := Forward(makeJSONLFile(t, lines), srv.URL, Options{}); err != nil {
		t.Fatal(err)
	}
	bodies, _ := rs.snapshot()
	for i, want := range lines {
		if string(bodies[i]) != want {
			t.Errorf("POST %d order broken: got %q, want %q", i, bodies[i], want)
		}
	}
}

// mTLS test cycles ----------------------------------------------------

// httpsTestSetup stands up an httptest.NewTLSServer (self-signed cert)
// and writes its server cert PEM to a temp file the test can pass as
// --mtls-ca. Returns the server, the path to the CA PEM, and a cleanup.
func httpsTestSetup(t *testing.T, handler http.HandlerFunc) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)

	caPath := writeTempFile(t, "ca.pem", certToPEM(t, srv.Certificate()))
	return srv, caPath
}

func writeTempFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func certToPEM(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func TestForwardOverHTTPSWithCAVerifies(t *testing.T) {
	rs := newRecordingServer(200)
	srv, caPath := httpsTestSetup(t, rs.handler())

	jsonl := makeJSONLFile(t, []string{`{"entry_hash":"a"}`})
	res, err := Forward(jsonl, srv.URL, Options{
		MTLSCAPath: caPath,
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if res.Forwarded != 1 {
		t.Errorf("forwarded = %d, want 1", res.Forwarded)
	}
}

func TestForwardOverHTTPSWithoutCARejectsSelfSigned(t *testing.T) {
	rs := newRecordingServer(200)
	srv := httptest.NewTLSServer(rs.handler())
	defer srv.Close()

	jsonl := makeJSONLFile(t, []string{`{"entry_hash":"a"}`})
	res, _ := Forward(jsonl, srv.URL, Options{}) // No CA, no skip-verify.
	if res.Failed != 1 {
		t.Errorf("self-signed cert without CA should fail; failed=%d", res.Failed)
	}
}

func TestForwardInsecureSkipVerifyAcceptsSelfSigned(t *testing.T) {
	rs := newRecordingServer(200)
	srv := httptest.NewTLSServer(rs.handler())
	defer srv.Close()

	jsonl := makeJSONLFile(t, []string{`{"entry_hash":"a"}`})
	res, err := Forward(jsonl, srv.URL, Options{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if res.Forwarded != 1 {
		t.Errorf("--insecure-skip-verify should accept self-signed; forwarded=%d failed=%d",
			res.Forwarded, res.Failed)
	}
}

func TestForwardWithClientCertAuthSucceeds(t *testing.T) {
	// Generate an Ed25519 client keypair + self-signed certificate.
	clientCertPEM, clientKeyPEM, clientCert := genEd25519ClientCert(t)
	clientCertPath := writeTempFile(t, "client.crt", clientCertPEM)
	clientKeyPath := writeTempFile(t, "client.key", clientKeyPEM)

	// Stand up an httptest TLS server that requires + verifies client certs.
	rs := newRecordingServer(200)
	srv := httptest.NewUnstartedServer(rs.handler())
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(clientCert)
	srv.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCAs,
	}
	srv.StartTLS()
	defer srv.Close()

	caPath := writeTempFile(t, "ca.pem", certToPEM(t, srv.Certificate()))

	jsonl := makeJSONLFile(t, []string{`{"entry_hash":"a"}`})
	res, err := Forward(jsonl, srv.URL, Options{
		MTLSCertPath: clientCertPath,
		MTLSKeyPath:  clientKeyPath,
		MTLSCAPath:   caPath,
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if res.Forwarded != 1 {
		t.Errorf("client-cert auth should succeed; forwarded=%d failed=%d",
			res.Forwarded, res.Failed)
	}
}

func TestForwardWithoutClientCertWhenServerRequiresFails(t *testing.T) {
	// Server requires a client cert; agent doesn't supply one.
	rs := newRecordingServer(200)
	srv := httptest.NewUnstartedServer(rs.handler())
	srv.TLS = &tls.Config{
		ClientAuth: tls.RequireAnyClientCert,
	}
	srv.StartTLS()
	defer srv.Close()

	caPath := writeTempFile(t, "ca.pem", certToPEM(t, srv.Certificate()))

	jsonl := makeJSONLFile(t, []string{`{"entry_hash":"a"}`})
	res, _ := Forward(jsonl, srv.URL, Options{
		MTLSCAPath: caPath, // CA only; no client cert
	})
	if res.Failed != 1 {
		t.Errorf("missing client cert against require-cert server should fail; failed=%d",
			res.Failed)
	}
}

func TestForwardErrorsWhenOnlyMTLSCertGivenNoKey(t *testing.T) {
	clientCertPEM, _, _ := genEd25519ClientCert(t)
	jsonl := makeJSONLFile(t, []string{`{}`})
	_, err := Forward(jsonl, "https://example.invalid/",
		Options{MTLSCertPath: writeTempFile(t, "c.pem", clientCertPEM)})
	if err == nil {
		t.Error("expected error when --mtls-cert given without --mtls-key, got nil")
	}
}

func TestForwardErrorsWhenOnlyMTLSKeyGivenNoCert(t *testing.T) {
	_, clientKeyPEM, _ := genEd25519ClientCert(t)
	jsonl := makeJSONLFile(t, []string{`{}`})
	_, err := Forward(jsonl, "https://example.invalid/",
		Options{MTLSKeyPath: writeTempFile(t, "k.pem", clientKeyPEM)})
	if err == nil {
		t.Error("expected error when --mtls-key given without --mtls-cert, got nil")
	}
}

func TestForwardErrorsWhenMTLSFlagsGivenWithHTTPURL(t *testing.T) {
	clientCertPEM, clientKeyPEM, _ := genEd25519ClientCert(t)
	jsonl := makeJSONLFile(t, []string{`{}`})
	_, err := Forward(jsonl, "http://example.invalid/", Options{
		MTLSCertPath: writeTempFile(t, "c.pem", clientCertPEM),
		MTLSKeyPath:  writeTempFile(t, "k.pem", clientKeyPEM),
	})
	if err == nil {
		t.Error("expected error when mTLS flags given with http:// URL, got nil")
	}
}

func TestForwardErrorsOnMissingMTLSCertFile(t *testing.T) {
	_, err := Forward("/dev/null", "https://example.invalid/", Options{
		MTLSCertPath: "/nonexistent/cert.pem",
		MTLSKeyPath:  "/nonexistent/key.pem",
	})
	if err == nil {
		t.Error("expected error on missing cert file, got nil")
	}
}

// genEd25519ClientCert mints a self-signed Ed25519 keypair + cert
// suitable as a client credential. Returns the cert PEM bytes, the
// private key PEM bytes (PKCS#8), and the parsed *x509.Certificate.
func genEd25519ClientCert(t *testing.T) ([]byte, []byte, *x509.Certificate) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "lemma-agent-test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, cert
}
