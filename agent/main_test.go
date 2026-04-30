package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNoArgsPrintsVersionAndSubcommandList(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(nil, &stdout, &stderr)
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
}

func TestVersionFlag(t *testing.T) {
	for _, arg := range []string{"version", "--version", "-v"} {
		t.Run(arg, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run([]string{arg}, &stdout, &stderr)
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
	code := run([]string{"frobulate"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("exit code %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "frobulate") {
		t.Errorf("error should name the unknown subcommand; got:\n%s", stderr.String())
	}
}

func TestVerifyMissingArgsExitsTwo(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"verify"}, &stdout, &stderr)
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

	mainFixtureLine0 = `{"event":{"class_uid":2003,"activity_id":1,"time":1700000000,"metadata":{"uid":"fixture-0"}},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","entry_hash":"ad45fdb920ab0ac996b793afa2785983d0fab8a5bf53ca12ed506baf5505249c","signature":"4a4570e276691556d546902f00c76d0d30e504a75d6f3221b7508e5492f49787bd0132553b8f8d5d41d4156014812a76c6713fd448310d7bcf9859c67e373a05","signer_key_id":"ed25519:56475aa75463474c","signed_at":"2026-01-01T00:00:00Z","provenance":[{"stage":"storage","actor":"TestProducer","timestamp":"2026-01-01T00:00:00Z","content_hash":"ad45fdb920ab0ac996b793afa2785983d0fab8a5bf53ca12ed506baf5505249c"}]}`
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
	code := run([]string{"verify", logPath, "--keys-dir", keysDir}, &stdout, &stderr)
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
	bad := strings.Replace(mainFixtureLine0, `"signature":"4a`, `"signature":"5a`, 1)
	if bad == mainFixtureLine0 {
		t.Fatal("test bug: tamper substring not found")
	}
	logPath, keysDir := writeMainFixture(t, []string{bad})
	var stdout, stderr bytes.Buffer
	code := run([]string{"verify", logPath, "--keys-dir", keysDir}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("exit code %d, want 1\nstdout:\n%s", code, stdout.String())
	}
	if !strings.Contains(stdout.String(), "VIOLATED") {
		t.Errorf("stdout should report VIOLATED; got:\n%s", stdout.String())
	}
}
