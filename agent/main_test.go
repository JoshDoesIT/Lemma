package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunPrintsVersionAndTrackingLines(t *testing.T) {
	var buf bytes.Buffer
	if err := run(&buf); err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	out := buf.String()

	wantVersion := "lemma-agent v" + Version
	if !strings.Contains(out, wantVersion) {
		t.Errorf("output missing version line %q\ngot:\n%s", wantVersion, out)
	}

	if !strings.Contains(out, "not yet implemented") {
		t.Errorf("output missing 'not yet implemented' marker\ngot:\n%s", out)
	}

	if !strings.Contains(out, "#25") {
		t.Errorf("output missing '#25' tracking reference\ngot:\n%s", out)
	}
}

func TestVersionIsSemver(t *testing.T) {
	parts := strings.Split(Version, ".")
	if len(parts) != 3 {
		t.Fatalf("Version %q is not three dotted parts", Version)
	}
}
