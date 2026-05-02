package main

import (
	"bytes"
	"encoding/json"
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
