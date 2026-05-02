// Command lemma-agent is the federated Lemma Agent binary.
//
// In this slice the agent verifies signed evidence logs (including
// CRL- and lifecycle-driven revocation), signs single OCSF events,
// ingests batches of events into a Go-managed evidence log, mints
// producer keys, and forwards signed envelopes to a Control Plane
// URL — all without going through Python. Future slices will add
// mTLS, the receiving Control Plane, and real install/status/sync
// wiring (tracked under #25).
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/JoshDoesIT/Lemma/agent/internal/crl"
	"github.com/JoshDoesIT/Lemma/agent/internal/crypto"
	"github.com/JoshDoesIT/Lemma/agent/internal/evidencelog"
	"github.com/JoshDoesIT/Lemma/agent/internal/forwarder"
	"github.com/JoshDoesIT/Lemma/agent/internal/keystore"
	"github.com/JoshDoesIT/Lemma/agent/internal/signer"
	"github.com/JoshDoesIT/Lemma/agent/internal/verifier"
)

// Version is the agent binary's semantic version. Bump on user-visible
// behavior changes.
const Version = "0.6.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stdout, "lemma-agent v%s\n", Version)
		fmt.Fprintln(stdout, "subcommands: verify, sign, ingest, keygen, forward")
		fmt.Fprintln(stdout, "Run `lemma-agent verify <jsonl> --keys-dir <dir> [--crl <path>]...` to verify a Lemma evidence log.")
		fmt.Fprintln(stdout, "Run `lemma-agent sign --keys-dir <dir> --producer <name>` to sign an OCSF event.")
		fmt.Fprintln(stdout, "Run `lemma-agent ingest <input> --keys-dir <dir> --evidence-dir <dir> --producer <name>` to ingest OCSF events into a Lemma evidence log.")
		fmt.Fprintln(stdout, "Run `lemma-agent keygen --keys-dir <dir> --producer <name>` to mint a producer keypair.")
		fmt.Fprintln(stdout, "Run `lemma-agent forward <jsonl> --to <url> [--mtls-cert <f>] [--mtls-key <f>] [--mtls-ca <f>]` to POST signed envelopes to a Control Plane (HTTP or HTTPS+mTLS).")
		fmt.Fprintln(stdout, "Federation install/status/sync wiring is tracked under #25.")
		return 0
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "lemma-agent v%s\n", Version)
		return 0
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "sign":
		return runSign(args[1:], stdin, stdout, stderr)
	case "ingest":
		return runIngest(args[1:], stdin, stdout, stderr)
	case "keygen":
		return runKeygen(args[1:], stdout, stderr)
	case "forward":
		return runForward(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "lemma-agent: unknown subcommand %q\n", args[0])
		fmt.Fprintln(stderr, "subcommands: verify, sign, ingest, keygen, forward")
		return 2
	}
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	usage := func() {
		fmt.Fprintln(stderr, "usage: lemma-agent verify <evidence.jsonl> --keys-dir <dir> [--crl <path>]...")
	}

	// Parse args in any order: one positional <file>, --keys-dir <dir>,
	// zero or more --crl <path>. Stdlib `flag` stops at the first
	// positional, so we walk by hand.
	var jsonlPath, keysDir string
	var crlPaths []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--keys-dir" || a == "-keys-dir":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "lemma-agent verify: --keys-dir requires a value")
				return 2
			}
			keysDir = args[i+1]
			i++
		case strings.HasPrefix(a, "--keys-dir=") || strings.HasPrefix(a, "-keys-dir="):
			_, keysDir, _ = strings.Cut(a, "=")
		case a == "--crl" || a == "-crl":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "lemma-agent verify: --crl requires a value")
				return 2
			}
			crlPaths = append(crlPaths, args[i+1])
			i++
		case strings.HasPrefix(a, "--crl=") || strings.HasPrefix(a, "-crl="):
			_, val, _ := strings.Cut(a, "=")
			crlPaths = append(crlPaths, val)
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(stderr, "lemma-agent verify: unknown flag %q\n", a)
			usage()
			return 2
		default:
			if jsonlPath != "" {
				fmt.Fprintln(stderr, "lemma-agent verify: too many positional arguments")
				usage()
				return 2
			}
			jsonlPath = a
		}
	}
	if jsonlPath == "" {
		usage()
		return 2
	}
	if keysDir == "" {
		fmt.Fprintln(stderr, "lemma-agent verify: --keys-dir is required")
		usage()
		return 2
	}

	// Load and verify each CRL up front. A bad CRL signature short-circuits
	// the run with exit 1 — silently ignoring an unverifiable CRL would let
	// an attacker suppress revocation by supplying a bad one.
	crls := make([]*crl.List, 0, len(crlPaths))
	for _, p := range crlPaths {
		list, err := crl.Load(p)
		if err != nil {
			fmt.Fprintf(stderr, "lemma-agent verify: %v\n", err)
			return 1
		}
		pemBytes, err := crypto.LoadPublicKeyByID(keysDir, list.IssuerKeyID)
		if err != nil {
			fmt.Fprintf(stderr,
				"lemma-agent verify: cannot resolve CRL issuer key %s under %s: %v\n",
				list.IssuerKeyID, keysDir, err)
			return 1
		}
		pub, err := crypto.LoadPublicKey(pemBytes)
		if err != nil {
			fmt.Fprintf(stderr, "lemma-agent verify: load CRL issuer key: %v\n", err)
			return 1
		}
		if !list.VerifySignature(pub) {
			fmt.Fprintf(stderr,
				"lemma-agent verify: CRL signature invalid — refusing to merge: %s\n", p)
			return 1
		}
		crls = append(crls, list)
	}

	results, err := verifier.Verify(jsonlPath, keysDir, verifier.Options{CRLs: crls})
	if err != nil {
		fmt.Fprintf(stderr, "lemma-agent verify: %v\n", err)
		return 2
	}

	proven, violated := 0, 0
	for _, r := range results {
		short := r.EntryHash
		if len(short) > 12 {
			short = short[:12]
		}
		switch r.Status {
		case "PROVEN":
			fmt.Fprintf(stdout, "%s… PROVEN\n", short)
			proven++
		case "VIOLATED":
			fmt.Fprintf(stdout, "%s… VIOLATED: %s\n", short, r.Reason)
			violated++
		default:
			fmt.Fprintf(stdout, "%s… %s\n", short, r.Status)
		}
	}
	fmt.Fprintf(stdout, "Verified %d entries: %d PROVEN, %d VIOLATED\n",
		len(results), proven, violated)

	// Mirror Python's `lemma evidence verify` behavior: when no CRL was
	// supplied the verifier's revocation picture is incomplete, so flag
	// it as an advisory (exit code unchanged).
	if len(crlPaths) == 0 {
		fmt.Fprintln(stdout,
			"Note: No CRL supplied; revocations issued elsewhere are not visible.")
	}

	if violated > 0 {
		return 1
	}
	return 0
}

func runSign(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	usage := func() {
		fmt.Fprintln(stderr,
			"usage: lemma-agent sign --keys-dir <dir> --producer <name> "+
				"[--prev-hash <hex>] [--event <path>] [--source-label <s>]")
	}

	var keysDir, producer, prevHash, eventPath, sourceLabel string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--keys-dir":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "lemma-agent sign: --keys-dir requires a value")
				return 2
			}
			keysDir = args[i+1]
			i++
		case strings.HasPrefix(a, "--keys-dir="):
			_, keysDir, _ = strings.Cut(a, "=")
		case a == "--producer":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "lemma-agent sign: --producer requires a value")
				return 2
			}
			producer = args[i+1]
			i++
		case strings.HasPrefix(a, "--producer="):
			_, producer, _ = strings.Cut(a, "=")
		case a == "--prev-hash":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "lemma-agent sign: --prev-hash requires a value")
				return 2
			}
			prevHash = args[i+1]
			i++
		case strings.HasPrefix(a, "--prev-hash="):
			_, prevHash, _ = strings.Cut(a, "=")
		case a == "--event":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "lemma-agent sign: --event requires a value")
				return 2
			}
			eventPath = args[i+1]
			i++
		case strings.HasPrefix(a, "--event="):
			_, eventPath, _ = strings.Cut(a, "=")
		case a == "--source-label":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "lemma-agent sign: --source-label requires a value")
				return 2
			}
			sourceLabel = args[i+1]
			i++
		case strings.HasPrefix(a, "--source-label="):
			_, sourceLabel, _ = strings.Cut(a, "=")
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(stderr, "lemma-agent sign: unknown flag %q\n", a)
			usage()
			return 2
		default:
			fmt.Fprintf(stderr, "lemma-agent sign: unexpected positional argument %q\n", a)
			usage()
			return 2
		}
	}
	if keysDir == "" {
		fmt.Fprintln(stderr, "lemma-agent sign: --keys-dir is required")
		usage()
		return 2
	}
	if producer == "" {
		fmt.Fprintln(stderr, "lemma-agent sign: --producer is required")
		usage()
		return 2
	}

	// Read event bytes from --event <path> or stdin.
	var eventBytes []byte
	var err error
	if eventPath != "" {
		eventBytes, err = os.ReadFile(eventPath)
		if err != nil {
			fmt.Fprintf(stderr, "lemma-agent sign: read event: %v\n", err)
			return 1
		}
		if sourceLabel == "" {
			sourceLabel = eventPath
		}
	} else {
		eventBytes, err = io.ReadAll(stdin)
		if err != nil {
			fmt.Fprintf(stderr, "lemma-agent sign: read stdin: %v\n", err)
			return 1
		}
		if sourceLabel == "" {
			sourceLabel = "-"
		}
	}
	if len(strings.TrimSpace(string(eventBytes))) == 0 {
		fmt.Fprintln(stderr, "lemma-agent sign: event is empty")
		return 2
	}

	// Resolve the producer's ACTIVE key.
	keyID, err := keystore.LoadActive(keysDir, producer)
	if err != nil {
		fmt.Fprintf(stderr, "lemma-agent sign: %v\n", err)
		return 1
	}
	priv, err := keystore.LoadPrivateKey(keysDir, producer, keyID)
	if err != nil {
		fmt.Fprintf(stderr, "lemma-agent sign: %v\n", err)
		return 1
	}

	sourceHash := sha256.Sum256(eventBytes)
	now := time.Now().UTC()
	line, err := signer.Build(signer.Inputs{
		EventJSON:         json.RawMessage(eventBytes),
		PrevHash:          prevHash,
		Producer:          producer,
		KeyID:             keyID,
		PrivateKey:        priv,
		SourceLabel:       sourceLabel,
		SourceContentHash: hex.EncodeToString(sourceHash[:]),
		SourceTimestamp:   now,
		StorageTimestamp:  now,
		SignedAt:          now,
	})
	if err != nil {
		fmt.Fprintf(stderr, "lemma-agent sign: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, string(line))
	return 0
}

func runIngest(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	usage := func() {
		fmt.Fprintln(stderr,
			"usage: lemma-agent ingest <input> --keys-dir <dir> --evidence-dir <dir> "+
				"--producer <name> [--source-label <s>]")
	}

	var inputPath, keysDir, evidenceDir, producer, sourceLabel string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--keys-dir":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "lemma-agent ingest: --keys-dir requires a value")
				return 2
			}
			keysDir = args[i+1]
			i++
		case strings.HasPrefix(a, "--keys-dir="):
			_, keysDir, _ = strings.Cut(a, "=")
		case a == "--evidence-dir":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "lemma-agent ingest: --evidence-dir requires a value")
				return 2
			}
			evidenceDir = args[i+1]
			i++
		case strings.HasPrefix(a, "--evidence-dir="):
			_, evidenceDir, _ = strings.Cut(a, "=")
		case a == "--producer":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "lemma-agent ingest: --producer requires a value")
				return 2
			}
			producer = args[i+1]
			i++
		case strings.HasPrefix(a, "--producer="):
			_, producer, _ = strings.Cut(a, "=")
		case a == "--source-label":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "lemma-agent ingest: --source-label requires a value")
				return 2
			}
			sourceLabel = args[i+1]
			i++
		case strings.HasPrefix(a, "--source-label="):
			_, sourceLabel, _ = strings.Cut(a, "=")
		case strings.HasPrefix(a, "-") && a != "-":
			fmt.Fprintf(stderr, "lemma-agent ingest: unknown flag %q\n", a)
			usage()
			return 2
		default:
			if inputPath != "" {
				fmt.Fprintln(stderr, "lemma-agent ingest: too many positional arguments")
				usage()
				return 2
			}
			inputPath = a
		}
	}
	if inputPath == "" {
		usage()
		return 2
	}
	if keysDir == "" {
		fmt.Fprintln(stderr, "lemma-agent ingest: --keys-dir is required")
		usage()
		return 2
	}
	if evidenceDir == "" {
		fmt.Fprintln(stderr, "lemma-agent ingest: --evidence-dir is required")
		usage()
		return 2
	}
	if producer == "" {
		fmt.Fprintln(stderr, "lemma-agent ingest: --producer is required")
		usage()
		return 2
	}

	// Read raw input bytes + format detection.
	var rawBytes []byte
	var isJSONL bool
	if inputPath == "-" {
		buf, err := io.ReadAll(stdin)
		if err != nil {
			fmt.Fprintf(stderr, "lemma-agent ingest: read stdin: %v\n", err)
			return 1
		}
		rawBytes = buf
		isJSONL = true
		if sourceLabel == "" {
			sourceLabel = "-"
		}
	} else {
		switch strings.ToLower(filepath.Ext(inputPath)) {
		case ".jsonl":
			isJSONL = true
		case ".json":
			isJSONL = false
		default:
			fmt.Fprintf(stderr,
				"lemma-agent ingest: unsupported file extension %q (use .json or .jsonl)\n",
				filepath.Ext(inputPath))
			return 2
		}
		buf, err := os.ReadFile(inputPath)
		if err != nil {
			fmt.Fprintf(stderr, "lemma-agent ingest: read %s: %v\n", inputPath, err)
			return 1
		}
		rawBytes = buf
		if sourceLabel == "" {
			sourceLabel = inputPath
		}
	}

	// Parse events.
	events, err := parseEvents(rawBytes, isJSONL)
	if err != nil {
		fmt.Fprintf(stderr, "lemma-agent ingest: %v\n", err)
		return 1
	}

	// Resolve key + private PEM.
	keyID, err := keystore.LoadActive(keysDir, producer)
	if err != nil {
		fmt.Fprintf(stderr, "lemma-agent ingest: %v\n", err)
		return 1
	}
	priv, err := keystore.LoadPrivateKey(keysDir, producer, keyID)
	if err != nil {
		fmt.Fprintf(stderr, "lemma-agent ingest: %v\n", err)
		return 1
	}

	// Build the source provenance once per call (sha256 of raw input).
	sourceContentHash := hashHex(rawBytes)

	log := evidencelog.Log{Dir: evidenceDir}

	// Pre-compute dedup-key sets for the days the input touches, so the
	// loop doesn't re-read those files for every event.
	daysTouched := map[string]string{} // YYYY-MM-DD -> file path
	for _, ev := range events {
		t, err := parseEventTime(ev)
		if err != nil {
			fmt.Fprintf(stderr, "lemma-agent ingest: %v\n", err)
			return 1
		}
		path := log.FilePathForTime(t)
		daysTouched[path] = path
	}
	dayPaths := make([]string, 0, len(daysTouched))
	for _, p := range daysTouched {
		dayPaths = append(dayPaths, p)
	}
	seen, err := log.DedupKeysForFiles(dayPaths)
	if err != nil {
		fmt.Fprintf(stderr, "lemma-agent ingest: %v\n", err)
		return 1
	}

	// Pull the chain head once; advance in memory across the batch.
	prevHash, err := log.LatestEntryHash()
	if err != nil {
		fmt.Fprintf(stderr, "lemma-agent ingest: %v\n", err)
		return 1
	}

	now := time.Now().UTC()
	ingested, skipped := 0, 0
	for _, ev := range events {
		key, err := evidencelog.DedupKey(ev)
		if err != nil {
			fmt.Fprintf(stderr, "lemma-agent ingest: %v\n", err)
			return 1
		}
		if _, exists := seen[key]; exists {
			skipped++
			continue
		}
		t, err := parseEventTime(ev)
		if err != nil {
			fmt.Fprintf(stderr, "lemma-agent ingest: %v\n", err)
			return 1
		}
		dayPath := log.FilePathForTime(t)

		line, err := signer.Build(signer.Inputs{
			EventJSON:         ev,
			PrevHash:          prevHash,
			Producer:          producer,
			KeyID:             keyID,
			PrivateKey:        priv,
			SourceLabel:       sourceLabel,
			SourceContentHash: sourceContentHash,
			SourceTimestamp:   now,
			StorageTimestamp:  now,
			SignedAt:          now,
		})
		if err != nil {
			fmt.Fprintf(stderr, "lemma-agent ingest: build envelope: %v\n", err)
			return 1
		}
		if err := log.Append(dayPath, line); err != nil {
			fmt.Fprintf(stderr, "lemma-agent ingest: append: %v\n", err)
			return 1
		}
		// Advance the in-memory chain head.
		var head struct {
			EntryHash string `json:"entry_hash"`
		}
		if err := json.Unmarshal(line, &head); err != nil {
			fmt.Fprintf(stderr, "lemma-agent ingest: parse new entry: %v\n", err)
			return 1
		}
		prevHash = head.EntryHash
		seen[key] = struct{}{}
		ingested++
	}

	fmt.Fprintf(stdout, "%d ingested, %d skipped (duplicate).\n", ingested, skipped)
	return 0
}

// hashHex returns lowercase-hex SHA-256 of b.
func hashHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// parseEvents converts the raw input bytes into a slice of event JSON
// payloads. JSONL → one event per non-empty line; JSON → single object.
// Empty input yields an empty slice (zero events, no error).
func parseEvents(raw []byte, isJSONL bool) ([]json.RawMessage, error) {
	if isJSONL {
		var out []json.RawMessage
		scanner := bufio.NewScanner(strings.NewReader(string(raw)))
		scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			if !json.Valid([]byte(line)) {
				return nil, fmt.Errorf("parse JSONL line %d: invalid JSON", lineNo)
			}
			out = append(out, json.RawMessage(line))
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("scan JSONL: %w", err)
		}
		return out, nil
	}
	// Single JSON object.
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, nil
	}
	if !json.Valid(raw) {
		return nil, fmt.Errorf("parse JSON: invalid JSON")
	}
	return []json.RawMessage{json.RawMessage(raw)}, nil
}

// parseEventTime extracts the event's `time` field and parses it as
// ISO-8601 (accepting both Z and +HH:MM suffixes).
func parseEventTime(eventJSON json.RawMessage) (time.Time, error) {
	var probe struct {
		Time string `json:"time"`
	}
	if err := json.Unmarshal(eventJSON, &probe); err != nil {
		return time.Time{}, fmt.Errorf("parse event time: %w", err)
	}
	if probe.Time == "" {
		return time.Time{}, fmt.Errorf("event has no time field")
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05.000000Z07:00",
		"2006-01-02T15:04:05.999999Z07:00",
		"2006-01-02T15:04:05Z07:00",
		time.RFC3339Nano,
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, probe.Time); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse event time %q", probe.Time)
}

func runKeygen(args []string, stdout, stderr io.Writer) int {
	usage := func() {
		fmt.Fprintln(stderr, "usage: lemma-agent keygen --keys-dir <dir> --producer <name>")
	}

	var keysDir, producer string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--keys-dir":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "lemma-agent keygen: --keys-dir requires a value")
				return 2
			}
			keysDir = args[i+1]
			i++
		case strings.HasPrefix(a, "--keys-dir="):
			_, keysDir, _ = strings.Cut(a, "=")
		case a == "--producer":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "lemma-agent keygen: --producer requires a value")
				return 2
			}
			producer = args[i+1]
			i++
		case strings.HasPrefix(a, "--producer="):
			_, producer, _ = strings.Cut(a, "=")
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(stderr, "lemma-agent keygen: unknown flag %q\n", a)
			usage()
			return 2
		default:
			fmt.Fprintf(stderr, "lemma-agent keygen: unexpected positional argument %q\n", a)
			usage()
			return 2
		}
	}
	if keysDir == "" {
		fmt.Fprintln(stderr, "lemma-agent keygen: --keys-dir is required")
		usage()
		return 2
	}
	if producer == "" {
		fmt.Fprintln(stderr, "lemma-agent keygen: --producer is required")
		usage()
		return 2
	}

	keyID, created, err := keystore.GenerateKeypair(keysDir, producer)
	if err != nil {
		fmt.Fprintf(stderr, "lemma-agent keygen: %v\n", err)
		return 1
	}
	if created {
		fmt.Fprintf(stdout, "Generated %s for producer %s.\n", keyID, producer)
	} else {
		fmt.Fprintf(stdout, "Producer %s already has ACTIVE key %s.\n", producer, keyID)
	}
	return 0
}

func runForward(args []string, stdout, stderr io.Writer) int {
	usage := func() {
		fmt.Fprintln(stderr,
			"usage: lemma-agent forward <jsonl> --to <url> "+
				"[--header KEY=VALUE]... [--timeout SECONDS] "+
				"[--mtls-cert <file>] [--mtls-key <file>] [--mtls-ca <file>] "+
				"[--insecure-skip-verify]")
	}

	var jsonlPath, url string
	var mtlsCert, mtlsKey, mtlsCA string
	var insecureSkipVerify bool
	headers := map[string]string{}
	var timeoutSec int
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--to":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "lemma-agent forward: --to requires a value")
				return 2
			}
			url = args[i+1]
			i++
		case strings.HasPrefix(a, "--to="):
			_, url, _ = strings.Cut(a, "=")
		case a == "--header":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "lemma-agent forward: --header requires a value")
				return 2
			}
			k, v, ok := strings.Cut(args[i+1], "=")
			if !ok || k == "" {
				fmt.Fprintf(stderr, "lemma-agent forward: --header value %q must be KEY=VALUE\n", args[i+1])
				return 2
			}
			headers[k] = v
			i++
		case strings.HasPrefix(a, "--header="):
			_, val, _ := strings.Cut(a, "=")
			k, v, ok := strings.Cut(val, "=")
			if !ok || k == "" {
				fmt.Fprintf(stderr, "lemma-agent forward: --header value %q must be KEY=VALUE\n", val)
				return 2
			}
			headers[k] = v
		case a == "--timeout":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "lemma-agent forward: --timeout requires a value")
				return 2
			}
			n, err := parseTimeoutSeconds(args[i+1])
			if err != nil {
				fmt.Fprintf(stderr, "lemma-agent forward: %v\n", err)
				return 2
			}
			timeoutSec = n
			i++
		case strings.HasPrefix(a, "--timeout="):
			_, val, _ := strings.Cut(a, "=")
			n, err := parseTimeoutSeconds(val)
			if err != nil {
				fmt.Fprintf(stderr, "lemma-agent forward: %v\n", err)
				return 2
			}
			timeoutSec = n
		case a == "--mtls-cert":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "lemma-agent forward: --mtls-cert requires a value")
				return 2
			}
			mtlsCert = args[i+1]
			i++
		case strings.HasPrefix(a, "--mtls-cert="):
			_, mtlsCert, _ = strings.Cut(a, "=")
		case a == "--mtls-key":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "lemma-agent forward: --mtls-key requires a value")
				return 2
			}
			mtlsKey = args[i+1]
			i++
		case strings.HasPrefix(a, "--mtls-key="):
			_, mtlsKey, _ = strings.Cut(a, "=")
		case a == "--mtls-ca":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "lemma-agent forward: --mtls-ca requires a value")
				return 2
			}
			mtlsCA = args[i+1]
			i++
		case strings.HasPrefix(a, "--mtls-ca="):
			_, mtlsCA, _ = strings.Cut(a, "=")
		case a == "--insecure-skip-verify":
			insecureSkipVerify = true
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(stderr, "lemma-agent forward: unknown flag %q\n", a)
			usage()
			return 2
		default:
			if jsonlPath != "" {
				fmt.Fprintln(stderr, "lemma-agent forward: too many positional arguments")
				usage()
				return 2
			}
			jsonlPath = a
		}
	}
	if jsonlPath == "" {
		usage()
		return 2
	}
	if url == "" {
		fmt.Fprintln(stderr, "lemma-agent forward: --to is required")
		usage()
		return 2
	}

	if insecureSkipVerify {
		fmt.Fprintln(stderr,
			"lemma-agent forward: WARNING: --insecure-skip-verify disables server "+
				"certificate verification — use only against test infrastructure.")
	}

	opts := forwarder.Options{
		Headers:            headers,
		MTLSCertPath:       mtlsCert,
		MTLSKeyPath:        mtlsKey,
		MTLSCAPath:         mtlsCA,
		InsecureSkipVerify: insecureSkipVerify,
	}
	if timeoutSec > 0 {
		opts.Timeout = time.Duration(timeoutSec) * time.Second
	}

	res, err := forwarder.Forward(jsonlPath, url, opts)
	if err != nil {
		fmt.Fprintf(stderr, "lemma-agent forward: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "%d forwarded, %d failed.\n", res.Forwarded, res.Failed)
	if res.Failed > 0 {
		return 1
	}
	return 0
}

func parseTimeoutSeconds(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("--timeout must be a non-negative integer (seconds), got %q", s)
		}
		n = n*10 + int(c-'0')
	}
	if n == 0 && len(s) == 0 {
		return 0, fmt.Errorf("--timeout requires a value")
	}
	return n, nil
}
