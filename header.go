package dkim

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"sort"
	"strings"
)

const crlf = "\r\n"

type header []string

func readHeader(r *bufio.Reader) (header, error) {
	tr := textproto.NewReader(r)

	var h header
	for {
		l, err := tr.ReadLine()
		if err != nil {
			return h, fmt.Errorf("failed to read header: %v", err)
		}

		if len(l) == 0 {
			break
		} else if len(h) > 0 && (l[0] == ' ' || l[0] == '\t') {
			// This is a continuation line
			h[len(h)-1] += l + crlf
		} else {
			h = append(h, l+crlf)
		}
	}

	return h, nil
}

func writeHeader(w io.Writer, h header) error {
	for _, kv := range h {
		if _, err := w.Write([]byte(kv)); err != nil {
			return err
		}
	}
	_, err := w.Write([]byte(crlf))
	return err
}

func foldHeaderField(kv string) string {
	buf := bytes.NewBufferString(kv + crlf)

	line := make([]byte, 75) // 78 - len("\r\n\s")
	first := true
	var fold strings.Builder
	for len, err := buf.Read(line); err != io.EOF; len, err = buf.Read(line) {
		if first {
			first = false
		} else {
			fold.WriteString("\r\n ")
		}
		fold.Write(line[:len])
	}

	return fold.String()
}

func parseHeaderField(s string) (k string, v string) {
	kv := strings.SplitN(s, ":", 2)
	k = strings.TrimSpace(kv[0])
	if len(kv) > 1 {
		v = strings.TrimSpace(kv[1])
	}
	return
}

func parseHeaderParams(s string) (map[string]string, error) {
	pairs := strings.Split(s, ";")
	params := make(map[string]string)
	for _, s := range pairs {
		kv := strings.SplitN(s, "=", 2)
		if len(kv) != 2 {
			if strings.TrimSpace(s) == "" {
				continue
			}
			return params, errors.New("dkim: malformed header params")
		}

		params[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}
	return params, nil
}

func formatHeaderParams(params map[string]string) string {
	keys := make([]string, 0, len(params))
	found := false
	for k := range params {
		if k == "b" {
			found = true
		} else {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if found {
		keys = append(keys, "b")
	}

	var s string
	first := true
	for _, k := range keys {
		v := params[k]

		if first {
			first = false
		} else {
			s += " "
		}

		s += k + "=" + v + ";"
	}
	return s
}

type headerPicker struct {
	h header
	// next contains the index of the first header field to inspect on the
	// next Pick call, for each lower-cased header field name. Each Pick only
	// walks the header fields above the previously picked one, so the picked
	// fields are deterministically bound to their position in the header.
	// This keeps the mapping between the "h=" tag list and the signed header
	// fields stable across retries: re-running Pick on the same header always
	// selects the exact same header field instances, even if additional
	// fields sharing a signed name have been injected into the message.
	next map[string]int
}

func newHeaderPicker(h header) *headerPicker {
	return &headerPicker{
		h:    h,
		next: make(map[string]int),
	}
}

func (p *headerPicker) Pick(key string) string {
	key = strings.ToLower(key)
	// RFC 6376 section 3.7: header fields are identified by field name and
	// the header fields are presented to the signing/verification algorithm
	// from the bottom of the header block to the top. The first call for a
	// given name starts at the end of the header block, subsequent calls
	// continue right above the field returned by the previous call.
	at, ok := p.next[key]
	if !ok {
		at = len(p.h)
	}
	for i := at - 1; i >= 0; i-- {
		kv := p.h[i]
		k, _ := parseHeaderField(kv)

		if strings.ToLower(k) != key {
			continue
		}

		// Bind this "h=" entry to the concrete header field at index i: the
		// next call for the same name must not consider this field nor any
		// field below it again.
		p.next[key] = i
		return kv
	}

	return ""
}
