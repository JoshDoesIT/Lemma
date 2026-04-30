// Package canonjson emits JSON byte-for-byte identical to Python's
//
//	json.dumps(value, sort_keys=True, separators=(",", ":"))
//
// with the default ensure_ascii=True escaping. Lemma's signed-evidence
// chain hash and CRL signature both rely on that exact byte sequence;
// any drift here breaks Python ↔ Go parity at the cryptographic layer.
package canonjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"unicode/utf16"
)

// MarshalRaw canonicalises raw JSON bytes. The input is decoded with
// UseNumber so numeric tokens (e.g. integer class_uid) are preserved
// verbatim; the resulting tree is walked, map keys sorted ascending by
// raw bytes, and re-emitted with no inter-token whitespace.
func MarshalRaw(raw json.RawMessage) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := encode(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Marshal canonicalises a Go value already in the same shape MarshalRaw
// produces (map[string]any, []any, json.Number, string, bool, nil).
// Reserved for callers that built the structure by hand; envelope
// verification goes through MarshalRaw.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encode(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encode(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(string(t))
	case string:
		encodeString(buf, t)
	case []any:
		buf.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encode(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			encodeString(buf, k)
			buf.WriteByte(':')
			if err := encode(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonjson: unsupported type %T", v)
	}
	return nil
}

// encodeString writes s as a JSON string literal using Python's
// json.dumps(ensure_ascii=True) escape rules:
//
//	"\b" "\t" "\n" "\f" "\r"  for the named C escapes (0x08, 0x09, 0x0A, 0x0C, 0x0D)
//	"\""  "\\"               for the syntactic escapes
//	"\u00XX"                 for other 0x00–0x1F controls
//	"\uXXXX"                 for any rune > 0x7E (BMP code unit)
//	"\uHHHH\uLLLL"           UTF-16 surrogate pair for runes > U+FFFF
//
// Forward slash is NOT escaped (Python doesn't escape it by default).
func encodeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\b':
			buf.WriteString(`\b`)
		case '\t':
			buf.WriteString(`\t`)
		case '\n':
			buf.WriteString(`\n`)
		case '\f':
			buf.WriteString(`\f`)
		case '\r':
			buf.WriteString(`\r`)
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else if r <= 0x7E {
				buf.WriteRune(r)
			} else if r <= 0xFFFF {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				hi, lo := utf16.EncodeRune(r)
				fmt.Fprintf(buf, `\u%04x\u%04x`, hi, lo)
			}
		}
	}
	buf.WriteByte('"')
}
