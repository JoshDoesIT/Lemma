// Command lemma-agent is the federated Lemma Agent binary.
//
// This is a scaffold. The agent's eventual responsibility is to run inside
// target environments (K8s sidecar, systemd unit, bare-metal process), forward
// signed evidence envelopes to a Control Plane, and pull configuration. None
// of that is implemented yet; install/status/sync wiring is tracked under #25
// (Federated Agent Architecture).
package main

import (
	"fmt"
	"io"
	"os"
)

// Version is the agent binary's semantic version. Bump on user-visible
// behavior changes once the agent grows real functionality.
const Version = "0.1.0"

func run(w io.Writer) error {
	if _, err := fmt.Fprintf(w, "lemma-agent v%s\n", Version); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "not yet implemented; tracked under #25"); err != nil {
		return err
	}
	return nil
}

func main() {
	if err := run(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "lemma-agent:", err)
		os.Exit(1)
	}
}
