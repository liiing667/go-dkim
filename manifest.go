package dkim

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

// ManifestVersion is the current on-disk manifest format version.
const ManifestVersion = 1

// Manifest is a recoverable, ordered collection of message verification
// reports. A new message is appended without replacing earlier messages.
// Re-processing the same message ID replaces only that message's record, so a
// retry cannot silently discard a different message's result.
type Manifest struct {
	// Version is the manifest format version.
	Version int `json:"version"`
	// Messages contains one report per accepted message, in the order the
	// messages were first added.
	Messages []*MessageReport `json:"messages"`
}

// NewManifest returns an empty manifest.
func NewManifest() *Manifest {
	return &Manifest{
		Version:  ManifestVersion,
		Messages: make([]*MessageReport, 0),
	}
}

// Conclusion returns the worst message conclusion in the manifest. An empty
// manifest has StatusNone. This is useful for a batch consumer that must not
// report success when any retained message failed.
func (m *Manifest) Conclusion() Status {
	if m == nil || len(m.Messages) == 0 {
		return StatusNone
	}
	conclusion := StatusPass
	for _, message := range m.Messages {
		if message == nil {
			continue
		}
		status := message.FinalStatus()
		if statusRank(status) > statusRank(conclusion) {
			conclusion = status
		}
	}
	return conclusion
}

// Add adds report to the manifest. If a report with the same message ID
// already exists, that entry is replaced in place; all other messages and
// their order are preserved.
func (m *Manifest) Add(report *MessageReport) {
	if m == nil || report == nil {
		return
	}
	if m.Version == 0 {
		m.Version = ManifestVersion
	}
	report.normalize()
	if m.Messages == nil {
		m.Messages = make([]*MessageReport, 0)
	}

	if report.ID != "" {
		for i, existing := range m.Messages {
			if existing != nil && existing.ID == report.ID {
				m.Messages[i] = report
				return
			}
		}
	}
	m.Messages = append(m.Messages, report)
}

func (m *Manifest) normalize() error {
	if m.Version == 0 {
		m.Version = ManifestVersion
	}
	if m.Version != ManifestVersion {
		return fmt.Errorf("dkim: unsupported manifest version %d", m.Version)
	}
	if m.Messages == nil {
		m.Messages = make([]*MessageReport, 0)
	}

	seen := make(map[string]int, len(m.Messages))
	normalized := make([]*MessageReport, 0, len(m.Messages))
	for _, report := range m.Messages {
		if report == nil {
			continue
		}
		report.normalize()
		if report.ID != "" {
			if i, ok := seen[report.ID]; ok {
				normalized[i] = report
				continue
			}
			seen[report.ID] = len(normalized)
		}
		normalized = append(normalized, report)
	}
	m.Messages = normalized
	return nil
}

// ReadManifest decodes a manifest from r. Empty input is treated as a new
// manifest. For recovery, line-delimited message reports are accepted too: any
// complete records are kept while an incomplete trailing record is ignored.
func ReadManifest(r io.Reader) (*Manifest, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return decodeManifest(data)
}

func decodeManifest(data []byte) (*Manifest, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return NewManifest(), nil
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err == nil {
		if err := m.normalize(); err != nil {
			return nil, err
		}
		return &m, nil
	} else {
		// A JSON array of message reports was used by some early consumers.
		var messages []*MessageReport
		if arrayErr := json.Unmarshal(data, &messages); arrayErr == nil {
			m = Manifest{Version: ManifestVersion, Messages: messages}
			if err := m.normalize(); err != nil {
				return nil, err
			}
			return &m, nil
		}

		// Recover complete JSON-lines records from a file whose final record
		// was truncated, for instance after a process crash.
		if recovered, ok := recoverManifestLines(data); ok {
			return recovered, nil
		}
		return nil, fmt.Errorf("dkim: malformed manifest: %v", err)
	}
}

func recoverManifestLines(data []byte) (*Manifest, bool) {
	m := NewManifest()
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] != '{' {
			continue
		}

		var report MessageReport
		if err := json.Unmarshal(line, &report); err != nil {
			continue
		}
		if report.ID == "" && len(report.Signatures) == 0 && report.Conclusion == "" {
			continue
		}
		m.Add(&report)
	}
	if len(m.Messages) == 0 {
		return nil, false
	}
	if err := m.normalize(); err != nil {
		return nil, false
	}
	return m, true
}

// LoadManifestFile loads a manifest from path. A missing or empty file is an
// empty manifest. Invalid existing contents are reported as an error so a
// recovery operation never overwrites evidence it could not read.
func LoadManifestFile(path string) (*Manifest, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return NewManifest(), nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadManifest(f)
}

// WriteManifest writes m as pretty-printed JSON.
func WriteManifest(w io.Writer, m *Manifest) error {
	if m == nil {
		m = NewManifest()
	}
	if err := m.normalize(); err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(m)
}

// SaveManifestFile atomically writes m to path. The data is written to a
// temporary file in the same directory, synced, and renamed into place. A
// crash or write error therefore leaves the previous complete manifest
// untouched instead of publishing a half-written result file.
func SaveManifestFile(path string, m *Manifest) error {
	if m == nil {
		m = NewManifest()
	}
	if err := m.normalize(); err != nil {
		return err
	}

	var data bytes.Buffer
	enc := json.NewEncoder(&data)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return err
	}

	dir := filepath.Dir(path)
	base := filepath.Base(path)
	mode := os.FileMode(0600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}

	tmp, err := ioutil.TempFile(dir, "."+base+".tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(data.Bytes()); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	committed = true

	// Also sync the directory entry when the platform supports it, so the
	// rename itself survives a crash.
	if dirFile, err := os.Open(dir); err == nil {
		dirFile.Sync()
		dirFile.Close()
	}
	return nil
}

// UpdateManifestFile adds report to the manifest stored at path and atomically
// writes the result back. Existing message records are never dropped; a
// different message is appended, while re-processing the same message ID
// replaces only that record.
func UpdateManifestFile(path string, report *MessageReport) (*Manifest, error) {
	m, err := LoadManifestFile(path)
	if err != nil {
		return nil, err
	}
	m.Add(report)
	if err := SaveManifestFile(path, m); err != nil {
		return nil, err
	}
	return m, nil
}
