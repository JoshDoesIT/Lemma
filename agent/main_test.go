package main

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNoArgsPrintsVersionAndSubcommandList(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(nil, bytes.NewReader(nil), &stdout, &stderr)
	if code != 0 {
		t.Errorf("exit code %d, want 0", code)
	}

	out := stdout.String()
	if !strings.Contains(out, "lemma-agent v"+Version) {
		t.Errorf("missing version line; got:\n%s", out)
	}
	if !strings.Contains(out, "subcommands:") {
		t.Errorf("missing subcommands list; got:\n%s", out)
	}
	if !strings.Contains(out, "verify") {
		t.Errorf("subcommands list should mention 'verify'; got:\n%s", out)
	}
	if !strings.Contains(out, "sign") {
		t.Errorf("subcommands list should mention 'sign'; got:\n%s", out)
	}
	if !strings.Contains(out, "ingest") {
		t.Errorf("subcommands list should mention 'ingest'; got:\n%s", out)
	}
	if !strings.Contains(out, "keygen") {
		t.Errorf("subcommands list should mention 'keygen'; got:\n%s", out)
	}
	if !strings.Contains(out, "forward") {
		t.Errorf("subcommands list should mention 'forward'; got:\n%s", out)
	}
}

func TestVersionFlag(t *testing.T) {
	for _, arg := range []string{"version", "--version", "-v"} {
		t.Run(arg, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run([]string{arg}, bytes.NewReader(nil), &stdout, &stderr)
			if code != 0 {
				t.Errorf("exit code %d, want 0", code)
			}
			if !strings.Contains(stdout.String(), "lemma-agent v"+Version) {
				t.Errorf("missing version line; got:\n%s", stdout.String())
			}
		})
	}
}

func TestVersionIsSemver(t *testing.T) {
	parts := strings.Split(Version, ".")
	if len(parts) != 3 {
		t.Fatalf("Version %q is not three dotted parts", Version)
	}
}

func TestUnknownSubcommandExitsTwo(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"frobulate"}, bytes.NewReader(nil), &stdout, &stderr)
	if code != 2 {
		t.Errorf("exit code %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "frobulate") {
		t.Errorf("error should name the unknown subcommand; got:\n%s", stderr.String())
	}
}

func TestVerifyMissingArgsExitsTwo(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"verify"}, bytes.NewReader(nil), &stdout, &stderr)
	if code != 2 {
		t.Errorf("exit code %d, want 2 (usage error)", code)
	}
	if !strings.Contains(stderr.String(), "usage") &&
		!strings.Contains(stderr.String(), "--keys-dir") {
		t.Errorf("error should explain usage; got:\n%s", stderr.String())
	}
}

// Same fixture as the verifier package's tests — pinned signed JSONL +
// PEM from a deterministic Ed25519 keypair (seed = bytes(range(32))).
const (
	mainFixturePEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=
-----END PUBLIC KEY-----
`
	mainFixtureProducer = "TestProducer"
	mainFixtureKeyID    = "ed25519:56475aa75463474c"

	mainFixtureLine0 = `{"event":{"class_uid":2003,"activity_id":1,"time":1700000000,"metadata":{"uid":"fixture-0","product":{"name":"TestProducer"}}},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","entry_hash":"f732ee4807b6c2b9f13acd72f406daf2f46a3b968215c34ccc89993a3ec577bf","signature":"a74c2115e069ddb6ab7a6335e910ff2dbd702befc34d1767c5674f0ba250ca66fb1d65350570e81f8304f35775dfde50494f9364a426bdff27b7428968c03100","signer_key_id":"ed25519:56475aa75463474c","signed_at":"2026-01-01T00:00:00+00:00","provenance":[{"stage":"storage","actor":"lemma.test","timestamp":"2026-01-01T00:00:00+00:00","content_hash":"f732ee4807b6c2b9f13acd72f406daf2f46a3b968215c34ccc89993a3ec577bf"}]}`

	// CRL revoking the fixture's signer key BEFORE signed_at — entry flips to VIOLATED.
	mainCRLRevokedBefore = `{"producer":"TestProducer","issued_at":"2026-01-02T00:00:00+00:00","revocations":[{"key_id":"ed25519:56475aa75463474c","revoked_at":"2025-12-01T00:00:00+00:00","reason":"leaked"}],"issuer_key_id":"ed25519:56475aa75463474c","signature":"5e54a867dfdaa6e02d8843441ce6dcb8385295164abf8280dab0d0cead81b870c04864d82b9afaea068d58510cb2d24b5befa3bfc8edfd4c25ae030d4a1f2c08"}`
)

func writeMainFixture(t *testing.T, lines []string) (logPath, keysDir string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "log.jsonl")
	if err := os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	keysDir = filepath.Join(dir, "keys")
	keyDir := filepath.Join(keysDir, mainFixtureProducer)
	if err := os.MkdirAll(keyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, mainFixtureKeyID+".public.pem"),
		[]byte(mainFixturePEM), 0o644); err != nil {
		t.Fatal(err)
	}
	return logPath, keysDir
}

func TestVerifySucceedsForPristineLog(t *testing.T) {
	logPath, keysDir := writeMainFixture(t, []string{mainFixtureLine0})
	var stdout, stderr bytes.Buffer
	code := run([]string{"verify", logPath, "--keys-dir", keysDir}, bytes.NewReader(nil), &stdout, &stderr)
	if code != 0 {
		t.Errorf("exit code %d, want 0\nstderr:\n%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "PROVEN") {
		t.Errorf("stdout should report PROVEN; got:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "1 PROVEN") {
		t.Errorf("summary should report 1 PROVEN; got:\n%s", stdout.String())
	}
}

func TestVerifyExitsOneForTamperedLog(t *testing.T) {
	bad := strings.Replace(mainFixtureLine0, `"signature":"a74c`, `"signature":"b74c`, 1)
	if bad == mainFixtureLine0 {
		t.Fatal("test bug: tamper substring not found")
	}
	logPath, keysDir := writeMainFixture(t, []string{bad})
	var stdout, stderr bytes.Buffer
	code := run([]string{"verify", logPath, "--keys-dir", keysDir}, bytes.NewReader(nil), &stdout, &stderr)
	if code != 1 {
		t.Errorf("exit code %d, want 1\nstdout:\n%s", code, stdout.String())
	}
	if !strings.Contains(stdout.String(), "VIOLATED") {
		t.Errorf("stdout should report VIOLATED; got:\n%s", stdout.String())
	}
}

// CRL flag + advisory tests --------------------------------------------

func writeMainCRL(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "crl.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVerifyMissingCRLAdvisoryWhenNoCRLFlag(t *testing.T) {
	logPath, keysDir := writeMainFixture(t, []string{mainFixtureLine0})
	var stdout, stderr bytes.Buffer
	code := run([]string{"verify", logPath, "--keys-dir", keysDir}, bytes.NewReader(nil), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code %d, want 0\nstderr:\n%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "No CRL supplied") {
		t.Errorf("stdout should mention the missing-CRL advisory; got:\n%s", stdout.String())
	}
}

func TestVerifyNoAdvisoryWhenCRLProvided(t *testing.T) {
	logPath, keysDir := writeMainFixture(t, []string{mainFixtureLine0})
	crlPath := writeMainCRL(t, mainCRLRevokedBefore)
	var stdout, stderr bytes.Buffer
	code := run([]string{"verify", logPath, "--keys-dir", keysDir, "--crl", crlPath}, bytes.NewReader(nil), &stdout, &stderr)
	// The fixture's key is revoked before signed_at → exit 1, VIOLATED.
	if code != 1 {
		t.Errorf("exit code %d, want 1\nstdout:\n%s", code, stdout.String())
	}
	if strings.Contains(stdout.String(), "No CRL supplied") {
		t.Errorf("advisory should not appear when --crl is given; got:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "VIOLATED") {
		t.Errorf("stdout should report VIOLATED; got:\n%s", stdout.String())
	}
}

func TestVerifyCRLFlagWithoutValueExitsTwo(t *testing.T) {
	logPath, keysDir := writeMainFixture(t, []string{mainFixtureLine0})
	var stdout, stderr bytes.Buffer
	code := run([]string{"verify", logPath, "--keys-dir", keysDir, "--crl"}, bytes.NewReader(nil), &stdout, &stderr)
	if code != 2 {
		t.Errorf("exit code %d, want 2 (usage)", code)
	}
}

func TestVerifyMultipleCRLFlagsAccepted(t *testing.T) {
	logPath, keysDir := writeMainFixture(t, []string{mainFixtureLine0})
	crl1 := writeMainCRL(t, mainCRLRevokedBefore)
	crl2 := writeMainCRL(t, mainCRLRevokedBefore)
	var stdout, stderr bytes.Buffer
	code := run([]string{"verify", logPath, "--keys-dir", keysDir,
		"--crl", crl1, "--crl", crl2}, bytes.NewReader(nil), &stdout, &stderr)
	if code != 1 {
		t.Errorf("exit code %d, want 1 (key revoked)\nstderr:\n%s", code, stderr.String())
	}
}

func TestVerifyTamperedCRLExitsOneBeforeWalkingEnvelopes(t *testing.T) {
	// Bad signature on the CRL must short-circuit before per-envelope checks.
	tampered := strings.Replace(mainCRLRevokedBefore,
		`"signature":"5e54a8`,
		`"signature":"6e54a8`, 1)
	if tampered == mainCRLRevokedBefore {
		t.Fatal("test bug: signature substring not found in CRL fixture")
	}
	logPath, keysDir := writeMainFixture(t, []string{mainFixtureLine0})
	crlPath := writeMainCRL(t, tampered)
	var stdout, stderr bytes.Buffer
	code := run([]string{"verify", logPath, "--keys-dir", keysDir, "--crl", crlPath}, bytes.NewReader(nil), &stdout, &stderr)
	if code != 1 {
		t.Errorf("exit code %d, want 1 (bad CRL)", code)
	}
	if !strings.Contains(stderr.String(), "CRL signature invalid") {
		t.Errorf("stderr should mention CRL signature failure; got:\n%s", stderr.String())
	}
	// The per-envelope walk must NOT have run, so no PROVEN/VIOLATED lines.
	if strings.Contains(stdout.String(), "PROVEN") || strings.Contains(stdout.String(), "VIOLATED") {
		t.Errorf("envelope walk should not run on bad CRL; got:\n%s", stdout.String())
	}
}

// Sign subcommand tests --------------------------------------------------

const signTestPrivPEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f
-----END PRIVATE KEY-----
`

const signTestMetaJSON = `{"keys":[{"key_id":"ed25519:56475aa75463474c","status":"ACTIVE","activated_at":"2026-01-01T00:00:00Z","retired_at":null,"revoked_at":null,"revoked_reason":"","successor_key_id":""}]}`

// writeSignFixture lays out a keys-dir with a real ACTIVE key the agent
// can use to sign.
func writeSignFixture(t *testing.T) (keysDir string) {
	t.Helper()
	dir := t.TempDir()
	prodDir := filepath.Join(dir, "Lemma")
	if err := os.MkdirAll(prodDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(prodDir, "meta.json"),
		[]byte(signTestMetaJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(prodDir, mainFixtureKeyID+".private.pem"),
		[]byte(signTestPrivPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(prodDir, mainFixtureKeyID+".public.pem"),
		[]byte(mainFixturePEM), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

const signTestEvent = `{"class_uid":2003,"class_name":"Compliance Finding","category_uid":2000,"category_name":"Findings","type_uid":200301,"activity_id":1,"time":"2026-04-30T12:00:00Z","metadata":{"version":"1.3.0","product":{"name":"Lemma"},"uid":"go-sign-1"}}`

func TestSignFromStdinProducesValidEnvelope(t *testing.T) {
	keysDir := writeSignFixture(t)
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"sign", "--keys-dir", keysDir, "--producer", "Lemma"},
		strings.NewReader(signTestEvent),
		&stdout, &stderr,
	)
	if code != 0 {
		t.Fatalf("exit code %d, want 0\nstderr:\n%s", code, stderr.String())
	}
	out := strings.TrimSpace(stdout.String())
	if out == "" {
		t.Fatal("stdout is empty; expected one envelope JSONL line")
	}
	for _, want := range []string{
		`"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000"`,
		`"signer_key_id":"ed25519:56475aa75463474c"`,
		`"signature":"`,
		`"entry_hash":"`,
		`"stage":"source"`,
		`"stage":"storage"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\ngot: %s", want, out)
		}
	}
}

func TestSignFromEventFileProducesValidEnvelope(t *testing.T) {
	keysDir := writeSignFixture(t)
	eventPath := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(eventPath, []byte(signTestEvent), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"sign", "--keys-dir", keysDir, "--producer", "Lemma", "--event", eventPath},
		bytes.NewReader(nil),
		&stdout, &stderr,
	)
	if code != 0 {
		t.Fatalf("exit code %d, want 0\nstderr:\n%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"signer_key_id"`) {
		t.Errorf("stdout missing signer_key_id; got:\n%s", stdout.String())
	}
}

func TestSignChainsViaPrevHashFlag(t *testing.T) {
	keysDir := writeSignFixture(t)
	customPrev := "deadbeef" + strings.Repeat("0", 56)
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"sign", "--keys-dir", keysDir, "--producer", "Lemma", "--prev-hash", customPrev},
		strings.NewReader(signTestEvent),
		&stdout, &stderr,
	)
	if code != 0 {
		t.Fatalf("exit code %d, want 0\nstderr:\n%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"prev_hash":"`+customPrev+`"`) {
		t.Errorf("expected prev_hash %q in output; got:\n%s",
			customPrev, stdout.String())
	}
}

func TestSignSubcommandRoundTripsThroughVerify(t *testing.T) {
	keysDir := writeSignFixture(t)
	var signOut, signErr bytes.Buffer
	signCode := run(
		[]string{"sign", "--keys-dir", keysDir, "--producer", "Lemma"},
		strings.NewReader(signTestEvent),
		&signOut, &signErr,
	)
	if signCode != 0 {
		t.Fatalf("sign failed: exit %d\nstderr:\n%s", signCode, signErr.String())
	}

	logPath := filepath.Join(t.TempDir(), "log.jsonl")
	if err := os.WriteFile(logPath, []byte(strings.TrimSpace(signOut.String())+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var verifyOut, verifyErr bytes.Buffer
	verifyCode := run(
		[]string{"verify", logPath, "--keys-dir", keysDir},
		bytes.NewReader(nil),
		&verifyOut, &verifyErr,
	)
	if verifyCode != 0 {
		t.Errorf("verify on Go-signed envelope failed: exit %d\nstdout:\n%s\nstderr:\n%s",
			verifyCode, verifyOut.String(), verifyErr.String())
	}
	if !strings.Contains(verifyOut.String(), "1 PROVEN") {
		t.Errorf("verify should report 1 PROVEN; got:\n%s", verifyOut.String())
	}
}

func TestSignMissingProducerExitsTwo(t *testing.T) {
	keysDir := writeSignFixture(t)
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"sign", "--keys-dir", keysDir},
		strings.NewReader(signTestEvent),
		&stdout, &stderr,
	)
	if code != 2 {
		t.Errorf("exit code %d, want 2 (usage)", code)
	}
}

func TestSignMissingKeysDirExitsTwo(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"sign", "--producer", "Lemma"},
		strings.NewReader(signTestEvent),
		&stdout, &stderr,
	)
	if code != 2 {
		t.Errorf("exit code %d, want 2 (usage)", code)
	}
}

func TestSignMissingActiveKeyExitsOne(t *testing.T) {
	// Empty keys-dir → no ACTIVE key for "Lemma".
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "Lemma"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Lemma", "meta.json"),
		[]byte(`{"keys":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"sign", "--keys-dir", dir, "--producer", "Lemma"},
		strings.NewReader(signTestEvent),
		&stdout, &stderr,
	)
	if code != 1 {
		t.Errorf("exit code %d, want 1 (no ACTIVE key)", code)
	}
}

// Ingest subcommand tests ----------------------------------------------

const ingestEvent1 = `{"class_uid":2003,"class_name":"Compliance Finding","category_uid":2000,"category_name":"Findings","type_uid":200301,"activity_id":1,"time":"2026-05-02T10:00:00Z","metadata":{"version":"1.3.0","product":{"name":"Lemma"},"uid":"ingest-1"}}`

const ingestEvent2 = `{"class_uid":2003,"class_name":"Compliance Finding","category_uid":2000,"category_name":"Findings","type_uid":200301,"activity_id":1,"time":"2026-05-02T11:00:00Z","metadata":{"version":"1.3.0","product":{"name":"Lemma"},"uid":"ingest-2"}}`

// Event timestamped on a different day so multi-day chain threading
// can be exercised.
const ingestEventDifferentDay = `{"class_uid":2003,"class_name":"Compliance Finding","category_uid":2000,"category_name":"Findings","type_uid":200301,"activity_id":1,"time":"2026-05-03T08:00:00Z","metadata":{"version":"1.3.0","product":{"name":"Lemma"},"uid":"ingest-3"}}`

func writeIngestFixture(t *testing.T) (keysDir, evidenceDir string) {
	t.Helper()
	keysDir = writeSignFixture(t)
	evidenceDir = filepath.Join(t.TempDir(), "evidence")
	if err := os.MkdirAll(evidenceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return keysDir, evidenceDir
}

func writeJSONLFile(t *testing.T, lines []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeJSONFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestIngestMissingFlagsExitsTwo(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no_keys_dir", []string{"ingest", "x.jsonl", "--evidence-dir", "/tmp/e", "--producer", "Lemma"}},
		{"no_evidence_dir", []string{"ingest", "x.jsonl", "--keys-dir", "/tmp/k", "--producer", "Lemma"}},
		{"no_producer", []string{"ingest", "x.jsonl", "--keys-dir", "/tmp/k", "--evidence-dir", "/tmp/e"}},
		{"no_input", []string{"ingest", "--keys-dir", "/tmp/k", "--evidence-dir", "/tmp/e", "--producer", "Lemma"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.args, bytes.NewReader(nil), &stdout, &stderr)
			if code != 2 {
				t.Errorf("exit code %d, want 2", code)
			}
		})
	}
}

func TestIngestSingleJSONFileWritesGenesisChainEntry(t *testing.T) {
	keysDir, evidenceDir := writeIngestFixture(t)
	eventPath := writeJSONFile(t, ingestEvent1)
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"ingest", eventPath, "--keys-dir", keysDir,
			"--evidence-dir", evidenceDir, "--producer", "Lemma"},
		bytes.NewReader(nil),
		&stdout, &stderr,
	)
	if code != 0 {
		t.Fatalf("exit %d, want 0\nstderr:\n%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "1 ingested") {
		t.Errorf("stdout missing '1 ingested'; got: %s", stdout.String())
	}
	dayFile := filepath.Join(evidenceDir, "2026-05-02.jsonl")
	body, err := os.ReadFile(dayFile)
	if err != nil {
		t.Fatalf("read day file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	if !strings.Contains(lines[0], `"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000"`) {
		t.Errorf("first entry should be genesis; got %s", lines[0])
	}
}

func TestIngestJSONLChainsAcrossEvents(t *testing.T) {
	keysDir, evidenceDir := writeIngestFixture(t)
	jsonlPath := writeJSONLFile(t, []string{ingestEvent1, ingestEvent2})
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"ingest", jsonlPath, "--keys-dir", keysDir,
			"--evidence-dir", evidenceDir, "--producer", "Lemma"},
		bytes.NewReader(nil),
		&stdout, &stderr,
	)
	if code != 0 {
		t.Fatalf("exit %d, want 0\nstderr:\n%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "2 ingested") {
		t.Errorf("stdout missing '2 ingested'; got: %s", stdout.String())
	}
	dayFile := filepath.Join(evidenceDir, "2026-05-02.jsonl")
	body, _ := os.ReadFile(dayFile)
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(lines))
	}
	// Chain: line 2's prev_hash == line 1's entry_hash.
	var first, second map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatal(err)
	}
	if first["entry_hash"] != second["prev_hash"] {
		t.Errorf("chain broken: line2 prev_hash=%v, line1 entry_hash=%v",
			second["prev_hash"], first["entry_hash"])
	}
}

func TestIngestDedupSkipsRepeatedUid(t *testing.T) {
	keysDir, evidenceDir := writeIngestFixture(t)
	jsonlPath := writeJSONLFile(t, []string{ingestEvent1})
	// First call: ingest.
	var out1, err1 bytes.Buffer
	code1 := run(
		[]string{"ingest", jsonlPath, "--keys-dir", keysDir,
			"--evidence-dir", evidenceDir, "--producer", "Lemma"},
		bytes.NewReader(nil), &out1, &err1,
	)
	if code1 != 0 {
		t.Fatalf("first ingest exit %d", code1)
	}
	// Second call with the same JSONL: should skip.
	var out2, err2 bytes.Buffer
	code2 := run(
		[]string{"ingest", jsonlPath, "--keys-dir", keysDir,
			"--evidence-dir", evidenceDir, "--producer", "Lemma"},
		bytes.NewReader(nil), &out2, &err2,
	)
	if code2 != 0 {
		t.Fatalf("second ingest exit %d, want 0\nstderr:\n%s", code2, err2.String())
	}
	if !strings.Contains(out2.String(), "0 ingested") {
		t.Errorf("expected '0 ingested' on dedup; got: %s", out2.String())
	}
	if !strings.Contains(out2.String(), "1 skipped") {
		t.Errorf("expected '1 skipped'; got: %s", out2.String())
	}
}

func TestIngestStdinJSONLChainsAcrossEvents(t *testing.T) {
	keysDir, evidenceDir := writeIngestFixture(t)
	stdinBody := ingestEvent1 + "\n" + ingestEvent2 + "\n"
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"ingest", "-", "--keys-dir", keysDir,
			"--evidence-dir", evidenceDir, "--producer", "Lemma"},
		strings.NewReader(stdinBody),
		&stdout, &stderr,
	)
	if code != 0 {
		t.Fatalf("exit %d, want 0\nstderr:\n%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "2 ingested") {
		t.Errorf("expected '2 ingested'; got: %s", stdout.String())
	}
}

func TestIngestMissingInputFileExitsOne(t *testing.T) {
	keysDir, evidenceDir := writeIngestFixture(t)
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"ingest", "/nonexistent/events.jsonl", "--keys-dir", keysDir,
			"--evidence-dir", evidenceDir, "--producer", "Lemma"},
		bytes.NewReader(nil), &stdout, &stderr,
	)
	if code != 1 {
		t.Errorf("exit %d, want 1 (file not found)", code)
	}
}

func TestIngestUnknownExtensionExitsTwo(t *testing.T) {
	keysDir, evidenceDir := writeIngestFixture(t)
	bogusPath := filepath.Join(t.TempDir(), "events.txt")
	if err := os.WriteFile(bogusPath, []byte("ignored"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"ingest", bogusPath, "--keys-dir", keysDir,
			"--evidence-dir", evidenceDir, "--producer", "Lemma"},
		bytes.NewReader(nil), &stdout, &stderr,
	)
	if code != 2 {
		t.Errorf("exit %d, want 2 (unknown extension)", code)
	}
}

func TestIngestSpansMultipleDaysWithChainContinuity(t *testing.T) {
	keysDir, evidenceDir := writeIngestFixture(t)
	jsonlPath := writeJSONLFile(t, []string{ingestEvent1, ingestEventDifferentDay})
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"ingest", jsonlPath, "--keys-dir", keysDir,
			"--evidence-dir", evidenceDir, "--producer", "Lemma"},
		bytes.NewReader(nil), &stdout, &stderr,
	)
	if code != 0 {
		t.Fatalf("exit %d, want 0\nstderr:\n%s", code, stderr.String())
	}
	// Two days, two files.
	day1Body, err := os.ReadFile(filepath.Join(evidenceDir, "2026-05-02.jsonl"))
	if err != nil {
		t.Fatalf("read day1: %v", err)
	}
	day2Body, err := os.ReadFile(filepath.Join(evidenceDir, "2026-05-03.jsonl"))
	if err != nil {
		t.Fatalf("read day2: %v", err)
	}
	day1Lines := strings.Split(strings.TrimSpace(string(day1Body)), "\n")
	day2Lines := strings.Split(strings.TrimSpace(string(day2Body)), "\n")
	if len(day1Lines) != 1 || len(day2Lines) != 1 {
		t.Fatalf("expected 1 line per day, got day1=%d day2=%d",
			len(day1Lines), len(day2Lines))
	}
	// day2's first entry chains off day1's last entry.
	var first, second map[string]any
	json.Unmarshal([]byte(day1Lines[0]), &first)
	json.Unmarshal([]byte(day2Lines[0]), &second)
	if first["entry_hash"] != second["prev_hash"] {
		t.Errorf("multi-day chain broken: day2 prev_hash=%v, day1 entry_hash=%v",
			second["prev_hash"], first["entry_hash"])
	}
}

func TestIngestPicksUpChainFromExistingLogOnSecondCall(t *testing.T) {
	keysDir, evidenceDir := writeIngestFixture(t)
	// First call: one event.
	first := writeJSONLFile(t, []string{ingestEvent1})
	var out1, err1 bytes.Buffer
	if code := run(
		[]string{"ingest", first, "--keys-dir", keysDir,
			"--evidence-dir", evidenceDir, "--producer", "Lemma"},
		bytes.NewReader(nil), &out1, &err1,
	); code != 0 {
		t.Fatalf("first ingest exit %d", code)
	}
	// Capture the entry hash that's now on disk.
	body, _ := os.ReadFile(filepath.Join(evidenceDir, "2026-05-02.jsonl"))
	var firstEnv map[string]any
	json.Unmarshal([]byte(strings.TrimSpace(string(body))), &firstEnv)
	prior := firstEnv["entry_hash"].(string)

	// Second call with a different uid (so dedup doesn't skip).
	second := writeJSONLFile(t, []string{ingestEvent2})
	var out2, err2 bytes.Buffer
	if code := run(
		[]string{"ingest", second, "--keys-dir", keysDir,
			"--evidence-dir", evidenceDir, "--producer", "Lemma"},
		bytes.NewReader(nil), &out2, &err2,
	); code != 0 {
		t.Fatalf("second ingest exit %d\nstderr:\n%s", code, err2.String())
	}
	body, _ = os.ReadFile(filepath.Join(evidenceDir, "2026-05-02.jsonl"))
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 entries after second ingest, got %d", len(lines))
	}
	var secondEnv map[string]any
	json.Unmarshal([]byte(lines[1]), &secondEnv)
	if secondEnv["prev_hash"] != prior {
		t.Errorf("second call should chain off prior on-disk entry: prev_hash=%v want %v",
			secondEnv["prev_hash"], prior)
	}
}

func TestIngestEmptyJSONLIsZeroIngestedNotError(t *testing.T) {
	keysDir, evidenceDir := writeIngestFixture(t)
	emptyPath := writeJSONLFile(t, []string{})
	// writeJSONLFile writes "\n" for empty list; that's OK — counts as no events.
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"ingest", emptyPath, "--keys-dir", keysDir,
			"--evidence-dir", evidenceDir, "--producer", "Lemma"},
		bytes.NewReader(nil), &stdout, &stderr,
	)
	if code != 0 {
		t.Errorf("exit %d, want 0 for empty input", code)
	}
	if !strings.Contains(stdout.String(), "0 ingested") {
		t.Errorf("expected '0 ingested'; got: %s", stdout.String())
	}
}

// Keygen subcommand tests ---------------------------------------------

func TestKeygenMissingFlagsExitsTwo(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no_keys_dir", []string{"keygen", "--producer", "Lemma"}},
		{"no_producer", []string{"keygen", "--keys-dir", "/tmp/k"}},
		{"both_missing", []string{"keygen"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.args, bytes.NewReader(nil), &stdout, &stderr)
			if code != 2 {
				t.Errorf("exit %d, want 2 (usage)\nstderr:\n%s", code, stderr.String())
			}
		})
	}
}

func TestKeygenFreshMintsKeyAndPrintsKeyID(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"keygen", "--keys-dir", dir, "--producer", "Lemma"},
		bytes.NewReader(nil), &stdout, &stderr,
	)
	if code != 0 {
		t.Fatalf("exit %d, want 0\nstderr:\n%s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "Generated ed25519:") {
		t.Errorf("stdout missing 'Generated ed25519:' line; got:\n%s", out)
	}
	if !strings.Contains(out, "for producer Lemma") {
		t.Errorf("stdout missing producer name; got:\n%s", out)
	}
	// Files exist on disk.
	prodDir := filepath.Join(dir, "Lemma")
	if _, err := os.Stat(filepath.Join(prodDir, "meta.json")); err != nil {
		t.Errorf("meta.json missing: %v", err)
	}
}

func TestKeygenIdempotentSecondCallReturnsSameID(t *testing.T) {
	dir := t.TempDir()
	var out1 bytes.Buffer
	if code := run(
		[]string{"keygen", "--keys-dir", dir, "--producer", "Lemma"},
		bytes.NewReader(nil), &out1, &bytes.Buffer{},
	); code != 0 {
		t.Fatalf("first keygen exit %d", code)
	}
	var out2, err2 bytes.Buffer
	code := run(
		[]string{"keygen", "--keys-dir", dir, "--producer", "Lemma"},
		bytes.NewReader(nil), &out2, &err2,
	)
	if code != 0 {
		t.Fatalf("second keygen exit %d\nstderr:\n%s", code, err2.String())
	}
	if !strings.Contains(out2.String(), "already has ACTIVE key") {
		t.Errorf("idempotent stdout missing 'already has ACTIVE key'; got:\n%s",
			out2.String())
	}
}

func TestKeygenRoundTripsThroughSignAndVerify(t *testing.T) {
	keysDir := t.TempDir()
	// 1. Mint a fresh key via the agent.
	var keygenOut, keygenErr bytes.Buffer
	if code := run(
		[]string{"keygen", "--keys-dir", keysDir, "--producer", "Lemma"},
		bytes.NewReader(nil), &keygenOut, &keygenErr,
	); code != 0 {
		t.Fatalf("keygen exit %d\nstderr:\n%s", code, keygenErr.String())
	}

	// 2. Sign an OCSF event with that key.
	const ev = `{"class_uid":2003,"class_name":"Compliance Finding","category_uid":2000,"category_name":"Findings","type_uid":200301,"activity_id":1,"time":"2026-05-02T12:00:00Z","metadata":{"version":"1.3.0","product":{"name":"Lemma"},"uid":"keygen-rt"}}`
	var signOut, signErr bytes.Buffer
	if code := run(
		[]string{"sign", "--keys-dir", keysDir, "--producer", "Lemma"},
		strings.NewReader(ev), &signOut, &signErr,
	); code != 0 {
		t.Fatalf("sign exit %d\nstderr:\n%s", code, signErr.String())
	}

	// 3. Write the signed envelope to a log file and verify.
	logPath := filepath.Join(t.TempDir(), "log.jsonl")
	if err := os.WriteFile(logPath, []byte(strings.TrimSpace(signOut.String())+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var verifyOut, verifyErr bytes.Buffer
	if code := run(
		[]string{"verify", logPath, "--keys-dir", keysDir},
		bytes.NewReader(nil), &verifyOut, &verifyErr,
	); code != 0 {
		t.Errorf("verify exit %d\nstdout:\n%s\nstderr:\n%s",
			code, verifyOut.String(), verifyErr.String())
	}
	if !strings.Contains(verifyOut.String(), "1 PROVEN") {
		t.Errorf("verify should report 1 PROVEN; got:\n%s", verifyOut.String())
	}
}

// Keyrotate subcommand tests --------------------------------------------

func TestKeyrotateMissingFlagsExitsTwo(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no_keys_dir", []string{"keyrotate", "--producer", "Lemma"}},
		{"no_producer", []string{"keyrotate", "--keys-dir", "/tmp/k"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.args, bytes.NewReader(nil), &stdout, &stderr)
			if code != 2 {
				t.Errorf("exit %d, want 2 (usage)\nstderr:\n%s", code, stderr.String())
			}
		})
	}
}

func TestKeyrotateWithoutPriorActiveExitsOne(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"keyrotate", "--keys-dir", dir, "--producer", "Lemma"},
		bytes.NewReader(nil), &stdout, &stderr,
	)
	if code != 1 {
		t.Errorf("exit %d, want 1 (no ACTIVE key)\nstderr:\n%s", code, stderr.String())
	}
}

func TestKeyrotatePrintsOldAndNewKeyIDs(t *testing.T) {
	dir := t.TempDir()
	// Bootstrap with a keygen.
	var bootOut bytes.Buffer
	if code := run(
		[]string{"keygen", "--keys-dir", dir, "--producer", "Lemma"},
		bytes.NewReader(nil), &bootOut, &bytes.Buffer{},
	); code != 0 {
		t.Fatalf("bootstrap keygen exit %d", code)
	}

	var rotOut, rotErr bytes.Buffer
	code := run(
		[]string{"keyrotate", "--keys-dir", dir, "--producer", "Lemma"},
		bytes.NewReader(nil), &rotOut, &rotErr,
	)
	if code != 0 {
		t.Fatalf("keyrotate exit %d\nstderr:\n%s", code, rotErr.String())
	}
	out := rotOut.String()
	if !strings.Contains(out, "Rotated Lemma:") {
		t.Errorf("stdout missing 'Rotated Lemma:'; got:\n%s", out)
	}
	if !strings.Contains(out, "retired") || !strings.Contains(out, "now ACTIVE") {
		t.Errorf("stdout missing retired/now ACTIVE markers; got:\n%s", out)
	}
}

func TestKeyrotateRoundTripsThroughSignAndVerify(t *testing.T) {
	keysDir := t.TempDir()
	if code := run(
		[]string{"keygen", "--keys-dir", keysDir, "--producer", "Lemma"},
		bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{},
	); code != 0 {
		t.Fatalf("keygen exit %d", code)
	}
	if code := run(
		[]string{"keyrotate", "--keys-dir", keysDir, "--producer", "Lemma"},
		bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{},
	); code != 0 {
		t.Fatalf("keyrotate exit %d", code)
	}

	const ev = `{"class_uid":2003,"class_name":"Compliance Finding","category_uid":2000,"category_name":"Findings","type_uid":200301,"activity_id":1,"time":"2026-05-02T12:00:00Z","metadata":{"version":"1.3.0","product":{"name":"Lemma"},"uid":"rotate-rt"}}`
	var signOut bytes.Buffer
	if code := run(
		[]string{"sign", "--keys-dir", keysDir, "--producer", "Lemma"},
		strings.NewReader(ev), &signOut, &bytes.Buffer{},
	); code != 0 {
		t.Fatalf("sign-after-rotate exit %d", code)
	}

	logPath := filepath.Join(t.TempDir(), "log.jsonl")
	if err := os.WriteFile(logPath, []byte(strings.TrimSpace(signOut.String())+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var verifyOut bytes.Buffer
	if code := run(
		[]string{"verify", logPath, "--keys-dir", keysDir},
		bytes.NewReader(nil), &verifyOut, &bytes.Buffer{},
	); code != 0 {
		t.Errorf("verify after rotate exit %d\nstdout:\n%s", code, verifyOut.String())
	}
	if !strings.Contains(verifyOut.String(), "1 PROVEN") {
		t.Errorf("verify should report 1 PROVEN; got:\n%s", verifyOut.String())
	}
}

// Keyrevoke subcommand tests --------------------------------------------

func TestKeyrevokeMissingFlagsExitsTwo(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no_keys_dir", []string{"keyrevoke", "--producer", "P", "--key-id", "K", "--reason", "R"}},
		{"no_producer", []string{"keyrevoke", "--keys-dir", "/tmp/k", "--key-id", "K", "--reason", "R"}},
		{"no_key_id", []string{"keyrevoke", "--keys-dir", "/tmp/k", "--producer", "P", "--reason", "R"}},
		{"no_reason", []string{"keyrevoke", "--keys-dir", "/tmp/k", "--producer", "P", "--key-id", "K"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.args, bytes.NewReader(nil), &stdout, &stderr)
			if code != 2 {
				t.Errorf("exit %d, want 2\nstderr:\n%s", code, stderr.String())
			}
		})
	}
}

func TestKeyrevokeUnknownKeyExitsOne(t *testing.T) {
	dir := t.TempDir()
	if code := run(
		[]string{"keygen", "--keys-dir", dir, "--producer", "Lemma"},
		bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{},
	); code != 0 {
		t.Fatalf("bootstrap keygen exit %d", code)
	}
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"keyrevoke", "--keys-dir", dir, "--producer", "Lemma",
			"--key-id", "ed25519:doesnotexist", "--reason", "leaked"},
		bytes.NewReader(nil), &stdout, &stderr,
	)
	if code != 1 {
		t.Errorf("exit %d, want 1\nstderr:\n%s", code, stderr.String())
	}
}

func TestKeyrevokeFlipsLifecycleAndBreaksSign(t *testing.T) {
	keysDir := t.TempDir()
	// Bootstrap key.
	var bootOut bytes.Buffer
	if code := run(
		[]string{"keygen", "--keys-dir", keysDir, "--producer", "Lemma"},
		bytes.NewReader(nil), &bootOut, &bytes.Buffer{},
	); code != 0 {
		t.Fatalf("keygen exit %d", code)
	}
	keyID := strings.TrimSuffix(
		strings.TrimPrefix(strings.TrimSpace(bootOut.String()), "Generated "),
		" for producer Lemma.",
	)

	// Revoke the only ACTIVE key.
	var revOut, revErr bytes.Buffer
	if code := run(
		[]string{"keyrevoke", "--keys-dir", keysDir, "--producer", "Lemma",
			"--key-id", keyID, "--reason", "key compromise"},
		bytes.NewReader(nil), &revOut, &revErr,
	); code != 0 {
		t.Fatalf("keyrevoke exit %d\nstderr:\n%s", code, revErr.String())
	}
	if !strings.Contains(revOut.String(), "Revoked "+keyID) {
		t.Errorf("revoke stdout missing 'Revoked %s'; got:\n%s", keyID, revOut.String())
	}

	// Lifecycle now shows REVOKED.
	metaBytes, err := os.ReadFile(filepath.Join(keysDir, "Lemma", "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(metaBytes), `"status": "REVOKED"`) {
		t.Errorf("meta.json should record REVOKED status; got:\n%s", string(metaBytes))
	}
	if !strings.Contains(string(metaBytes), `"revoked_reason": "key compromise"`) {
		t.Errorf("meta.json should record revoked_reason; got:\n%s", string(metaBytes))
	}

	// With no ACTIVE record left, sign exits 1.
	const ev = `{"class_uid":2003,"class_name":"Compliance Finding","category_uid":2000,"category_name":"Findings","type_uid":200301,"activity_id":1,"time":"2026-05-02T12:00:00Z","metadata":{"version":"1.3.0","product":{"name":"Lemma"},"uid":"revoke-rt"}}`
	var signOut, signErr bytes.Buffer
	if code := run(
		[]string{"sign", "--keys-dir", keysDir, "--producer", "Lemma"},
		strings.NewReader(ev), &signOut, &signErr,
	); code != 1 {
		t.Errorf("sign after revoke exit %d, want 1\nstdout:\n%s\nstderr:\n%s",
			code, signOut.String(), signErr.String())
	}
}

func TestKeyrevokeAfterRotateLeavesActiveKeyUsable(t *testing.T) {
	keysDir := t.TempDir()
	var bootOut bytes.Buffer
	if code := run(
		[]string{"keygen", "--keys-dir", keysDir, "--producer", "Lemma"},
		bytes.NewReader(nil), &bootOut, &bytes.Buffer{},
	); code != 0 {
		t.Fatalf("keygen exit %d", code)
	}
	oldKeyID := strings.TrimSuffix(
		strings.TrimPrefix(strings.TrimSpace(bootOut.String()), "Generated "),
		" for producer Lemma.",
	)

	if code := run(
		[]string{"keyrotate", "--keys-dir", keysDir, "--producer", "Lemma"},
		bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{},
	); code != 0 {
		t.Fatalf("keyrotate exit %d", code)
	}

	// Revoke the now-RETIRED original key.
	if code := run(
		[]string{"keyrevoke", "--keys-dir", keysDir, "--producer", "Lemma",
			"--key-id", oldKeyID, "--reason", "post-retirement compromise"},
		bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{},
	); code != 0 {
		t.Fatalf("keyrevoke on retired key exit %d", code)
	}

	// Sign with the still-ACTIVE rotated key should still succeed.
	const ev = `{"class_uid":2003,"class_name":"Compliance Finding","category_uid":2000,"category_name":"Findings","type_uid":200301,"activity_id":1,"time":"2026-05-02T12:00:00Z","metadata":{"version":"1.3.0","product":{"name":"Lemma"},"uid":"post-rotate"}}`
	var signOut bytes.Buffer
	if code := run(
		[]string{"sign", "--keys-dir", keysDir, "--producer", "Lemma"},
		strings.NewReader(ev), &signOut, &bytes.Buffer{},
	); code != 0 {
		t.Errorf("sign with ACTIVE rotated key exit %d", code)
	}
	if signOut.Len() == 0 {
		t.Error("sign produced no envelope")
	}
}

// Forward subcommand tests --------------------------------------------

func TestForwardMissingFlagsExitsTwo(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no_input", []string{"forward", "--to", "http://localhost"}},
		{"no_to", []string{"forward", "/tmp/x.jsonl"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.args, bytes.NewReader(nil), &stdout, &stderr)
			if code != 2 {
				t.Errorf("exit %d, want 2 (usage)", code)
			}
		})
	}
}

func TestForwardSuccessReportsAllForwarded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	jsonl := filepath.Join(t.TempDir(), "envelopes.jsonl")
	body := `{"entry_hash":"a"}` + "\n" + `{"entry_hash":"b"}` + "\n"
	if err := os.WriteFile(jsonl, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"forward", jsonl, "--to", srv.URL},
		bytes.NewReader(nil), &stdout, &stderr,
	)
	if code != 0 {
		t.Fatalf("exit %d, want 0\nstderr:\n%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "2 forwarded, 0 failed.") {
		t.Errorf("stdout missing summary; got:\n%s", stdout.String())
	}
}

func TestForwardAnyFailureExitsOne(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	jsonl := filepath.Join(t.TempDir(), "envelopes.jsonl")
	if err := os.WriteFile(jsonl, []byte(`{"entry_hash":"a"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"forward", jsonl, "--to", srv.URL},
		bytes.NewReader(nil), &stdout, &stderr,
	)
	if code != 1 {
		t.Errorf("exit %d, want 1 (any failure)", code)
	}
	if !strings.Contains(stdout.String(), "0 forwarded, 1 failed.") {
		t.Errorf("stdout missing summary; got:\n%s", stdout.String())
	}
}

func TestForwardHeaderFlagPropagatesToRequest(t *testing.T) {
	gotAuth := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	jsonl := filepath.Join(t.TempDir(), "envelopes.jsonl")
	if err := os.WriteFile(jsonl, []byte(`{"entry_hash":"a"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"forward", jsonl, "--to", srv.URL,
			"--header", "Authorization=Bearer xyz"},
		bytes.NewReader(nil), &stdout, &stderr,
	)
	if code != 0 {
		t.Fatalf("exit %d\nstderr:\n%s", code, stderr.String())
	}
	if gotAuth != "Bearer xyz" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer xyz")
	}
}

func TestForwardMissingFileExitsOne(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"forward", "/nonexistent.jsonl", "--to", "http://localhost"},
		bytes.NewReader(nil), &stdout, &stderr,
	)
	if code != 1 {
		t.Errorf("exit %d, want 1 (missing file)", code)
	}
}

func TestForwardBadHeaderFlagExitsTwo(t *testing.T) {
	jsonl := filepath.Join(t.TempDir(), "x.jsonl")
	if err := os.WriteFile(jsonl, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"forward", jsonl, "--to", "http://localhost",
			"--header", "noEqualsSign"},
		bytes.NewReader(nil), &stdout, &stderr,
	)
	if code != 2 {
		t.Errorf("exit %d, want 2 (bad --header)", code)
	}
}

func TestForwardEndToEndAgentSignThenForwardThenServerSeesEnvelope(t *testing.T) {
	// The agent signs an envelope with `sign`, then forwards the resulting
	// JSONL line with `forward`. The httptest server captures the body and
	// asserts it matches the sign output byte-for-byte (operationally:
	// "what the agent ingests ends up at the Control Plane intact").
	keysDir := writeSignFixture(t)

	var signOut, signErr bytes.Buffer
	if code := run(
		[]string{"sign", "--keys-dir", keysDir, "--producer", "Lemma"},
		strings.NewReader(signTestEvent),
		&signOut, &signErr,
	); code != 0 {
		t.Fatalf("sign exit %d\nstderr:\n%s", code, signErr.String())
	}
	envelopeLine := strings.TrimSpace(signOut.String())

	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = body
		w.WriteHeader(202)
	}))
	defer srv.Close()

	logPath := filepath.Join(t.TempDir(), "log.jsonl")
	if err := os.WriteFile(logPath, []byte(envelopeLine+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var fwdOut, fwdErr bytes.Buffer
	code := run(
		[]string{"forward", logPath, "--to", srv.URL},
		bytes.NewReader(nil), &fwdOut, &fwdErr,
	)
	if code != 0 {
		t.Fatalf("forward exit %d\nstderr:\n%s", code, fwdErr.String())
	}
	if string(receivedBody) != envelopeLine {
		t.Errorf("server received body differs from envelope:\n got:  %s\n want: %s",
			receivedBody, envelopeLine)
	}
}

// Forward mTLS CLI tests ----------------------------------------------

func TestForwardOnlyMTLSCertExitsOne(t *testing.T) {
	jsonl := filepath.Join(t.TempDir(), "x.jsonl")
	if err := os.WriteFile(jsonl, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"forward", jsonl, "--to", "https://example.invalid/",
			"--mtls-cert", "/tmp/c.pem"},
		bytes.NewReader(nil), &stdout, &stderr,
	)
	if code != 1 {
		t.Errorf("exit %d, want 1 (cert without key)", code)
	}
	if !strings.Contains(stderr.String(), "--mtls-cert and --mtls-key must be set together") {
		t.Errorf("stderr should explain the requirement; got:\n%s", stderr.String())
	}
}

func TestForwardMTLSWithHTTPURLExitsOne(t *testing.T) {
	jsonl := filepath.Join(t.TempDir(), "x.jsonl")
	if err := os.WriteFile(jsonl, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"forward", jsonl, "--to", "http://example.invalid/",
			"--insecure-skip-verify"},
		bytes.NewReader(nil), &stdout, &stderr,
	)
	if code != 1 {
		t.Errorf("exit %d, want 1 (mTLS flag with http://)", code)
	}
	if !strings.Contains(stderr.String(), "https://") {
		t.Errorf("stderr should mention https requirement; got:\n%s", stderr.String())
	}
}

func TestForwardInsecureSkipVerifyEmitsWarningToStderr(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	jsonl := filepath.Join(t.TempDir(), "x.jsonl")
	if err := os.WriteFile(jsonl, []byte(`{"entry_hash":"a"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"forward", jsonl, "--to", srv.URL, "--insecure-skip-verify"},
		bytes.NewReader(nil), &stdout, &stderr,
	)
	if code != 0 {
		t.Fatalf("exit %d, want 0\nstderr:\n%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "WARNING") {
		t.Errorf("stderr should carry a WARNING about --insecure-skip-verify; got:\n%s",
			stderr.String())
	}
	if !strings.Contains(stdout.String(), "1 forwarded, 0 failed.") {
		t.Errorf("stdout should report success; got:\n%s", stdout.String())
	}
}

func TestForwardOverHTTPSWithCAFlagSucceeds(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(202)
	}))
	defer srv.Close()

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, caPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	jsonl := filepath.Join(t.TempDir(), "x.jsonl")
	if err := os.WriteFile(jsonl, []byte(`{"entry_hash":"a"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"forward", jsonl, "--to", srv.URL, "--mtls-ca", caPath},
		bytes.NewReader(nil), &stdout, &stderr,
	)
	if code != 0 {
		t.Fatalf("exit %d, want 0\nstderr:\n%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "1 forwarded, 0 failed.") {
		t.Errorf("stdout should report success; got:\n%s", stdout.String())
	}
}

func TestForwardMissingMTLSCertFileExitsOne(t *testing.T) {
	jsonl := filepath.Join(t.TempDir(), "x.jsonl")
	if err := os.WriteFile(jsonl, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"forward", jsonl, "--to", "https://example.invalid/",
			"--mtls-cert", "/nonexistent/c.pem", "--mtls-key", "/nonexistent/k.pem"},
		bytes.NewReader(nil), &stdout, &stderr,
	)
	if code != 1 {
		t.Errorf("exit %d, want 1 (missing cert/key files)", code)
	}
}
