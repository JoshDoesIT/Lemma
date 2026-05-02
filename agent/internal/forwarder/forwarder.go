// Package forwarder POSTs Lemma signed-evidence envelopes to a Control
// Plane URL. One JSONL line per request, Content-Type application/json,
// 2xx counted as success and anything else as failure. Stateless — the
// caller manages chain bookkeeping and which envelopes to send.
//
// First slice of the federation arc on #25. mTLS, retry/backoff,
// resumable bookmarks, and bulk POSTs are all out of scope here;
// operators wrap this with shell tooling for now.
package forwarder

import (
	"bufio"
	"bytes"
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
// failures (e.g. file not found); per-request failures are surfaced via
// Result.Failed.
func Forward(jsonlPath, url string, opts Options) (Result, error) {
	f, err := os.Open(jsonlPath)
	if err != nil {
		return Result{}, fmt.Errorf("forwarder: open %s: %w", jsonlPath, err)
	}
	defer f.Close()

	client := &http.Client{Timeout: opts.Timeout}

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
