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

// HeaderInstance describes one concrete occurrence of a header field in the
// message generation consumed by a signature.
type HeaderInstance struct {
	// Index is the zero-based position of the header field in the complete
	// message header block.
	Index int
	// Name is the header field name as it appeared in the message.
	Name string
	// Value is the field value. Folded continuation lines are preserved.
	Value string
	// Raw is the complete header field, including folded whitespace and its
	// trailing CRLF.
	Raw string
}

func newHeaderInstance(index int, kv string) HeaderInstance {
	k, v := parseHeaderField(kv)
	return HeaderInstance{
		Index: index,
		Name:  k,
		Value: v,
		Raw:   kv,
	}
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
	// next maps a lower-case field name to the exclusive upper bound of the
	// next search. It only moves when a concrete header instance is selected.
	// Missing fields therefore do not consume an occurrence.
	next map[string]int
}

func newHeaderPicker(h header) *headerPicker {
	return &headerPicker{
		// Keep the parsed header block immutable for the lifetime of the
		// picker. A message generation must not change underneath a signature
		// binding.
		h:    append(header(nil), h...),
		next: make(map[string]int),
	}
}

func (p *headerPicker) pick(key string) (HeaderInstance, bool) {
	key = strings.ToLower(strings.TrimSpace(key))
	at, ok := p.next[key]
	if !ok {
		at = len(p.h)
	}
	for i := at - 1; i >= 0; i-- {
		kv := p.h[i]
		k, _ := parseHeaderField(kv)

		if !strings.EqualFold(k, key) {
			continue
		}

		// Bind this h= entry to the concrete header field at index i. The
		// next pick for the same name must continue above this field.
		p.next[key] = i
		return newHeaderInstance(i, kv), true
	}

	return HeaderInstance{}, false
}

func (p *headerPicker) Pick(key string) string {
	instance, ok := p.pick(key)
	if !ok {
		return ""
	}
	return instance.Raw
}

// Bind resolves keys against the picker's immutable header snapshot. It
// creates a fresh cursor and therefore always returns the same binding for the
// same header block and declaration order, even when called repeatedly.
func (p *headerPicker) Bind(keys []string) []HeaderInstance {
	return bindHeaderInstances(p.h, keys)
}

// bindHeaderInstances resolves every h= entry against one message generation.
// The returned instances are in declaration order and each entry is bound to
// exactly one physical header occurrence.
func bindHeaderInstances(h header, keys []string) []HeaderInstance {
	picker := newHeaderPicker(h)
	instances := make([]HeaderInstance, 0, len(keys))
	for _, key := range keys {
		instance, ok := picker.pick(key)
		if !ok {
			// RFC 6376 permits h= entries for fields that do not exist when
			// signing. They consume no header instance.
			continue
		}
		instances = append(instances, instance)
	}
	return instances
}
