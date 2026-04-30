// Command lemma-agent is the federated Lemma Agent binary.
//
// In this slice the agent verifies signed evidence logs end-to-end
// without going through Python. Future slices will add real install /
// status / sync wiring against a Control Plane (tracked under #25).
package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/JoshDoesIT/Lemma/agent/internal/verifier"
)

// Version is the agent binary's semantic version. Bump on user-visible
// behavior changes.
const Version = "0.2.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stdout, "lemma-agent v%s\n", Version)
		fmt.Fprintln(stdout, "subcommands: verify")
		fmt.Fprintln(stdout, "Run `lemma-agent verify <jsonl> --keys-dir <dir>` to verify a Lemma evidence log.")
		fmt.Fprintln(stdout, "Federation install/status/sync wiring is tracked under #25.")
		return 0
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "lemma-agent v%s\n", Version)
		return 0
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "lemma-agent: unknown subcommand %q\n", args[0])
		fmt.Fprintln(stderr, "subcommands: verify")
		return 2
	}
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	usage := func() {
		fmt.Fprintln(stderr, "usage: lemma-agent verify <evidence.jsonl> --keys-dir <dir>")
	}

	// Parse args in any order: one positional <file>, one flag --keys-dir.
	// Stdlib `flag` stops at the first positional, so we walk by hand.
	var jsonlPath, keysDir string
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
	results, err := verifier.Verify(jsonlPath, keysDir)
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
	if violated > 0 {
		return 1
	}
	return 0
}
