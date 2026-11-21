package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/mail"
	"net/textproto"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/emersion/go-dkim"
	"github.com/emersion/go-milter"
	"github.com/emersion/go-msgauth"
	"golang.org/x/crypto/ed25519"
)

var (
	signDomains    stringSliceFlag
	identity       string
	listenURI      string
	privateKeyPath string
	selector       string
	verbose        bool
)

var privateKey crypto.Signer

var signHeaderKeys = []string{
	"From",
	"Reply-To",
	"Subject",
	"Date",
	"To",
	"Cc",
	"Resent-Date",
	"Resent-From",
	"Resent-To",
	"Resent-Cc",
	"In-Reply-To",
	"References",
	"List-Id",
	"List-Help",
	"List-Unsubscribe",
	"List-Subscribe",
	"List-Post",
	"List-Owner",
	"List-Archive",
}

func init() {
	flag.Var(&signDomains, "d", "Domain(s) whose mail should be signed")
	flag.StringVar(&identity, "i", "", "Server identity (defaults to hostname)")
	flag.StringVar(&listenURI, "l", "unix:///tmp/dkim-milter.sock", "Listen URI")
	flag.StringVar(&privateKeyPath, "k", "", "Private key (PEM-formatted)")
	flag.StringVar(&selector, "s", "", "Selector")
	flag.BoolVar(&verbose, "v", false, "Enable verbose logging")
}

type stringSliceFlag []string

func (f *stringSliceFlag) String() string {
	return strings.Join(*f, ", ")
}

func (f *stringSliceFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

// session processes one message transaction at a time. Header, body, signer
// and verification state all belong to the current generation; starting a new
// message resets that state and cancels the previous generation's background
// work. Committed message IDs are retained so a retry can replay the same
// complete transaction or be rejected instead of being re-signed under a new
// header/body snapshot.
type session struct {
	mu sync.Mutex

	authResDelete []int
	headerBuf     bytes.Buffer
	headerNames   []string

	signDomain     string
	signHeaderKeys []string

	done       <-chan error
	verifyDone <-chan transactionVerifyOutcome
	pw         *io.PipeWriter
	verifs     []*dkim.Verification // only valid after verifyDone has a value
	signer     *dkim.Signer
	mw         io.Writer

	active      bool
	headersDone bool
	bodyStarted bool
	bodyDone    bool
	committed   bool

	generation   uint64
	messageID    string
	seen         map[string]bool
	headerDigest string
	bodyHasher   hash.Hash
	bodyLen      int64
	stage        string

	transactionCommitRecords map[string]*transactionCommitRecord
}

type transactionVerifyOutcome struct {
	verifs []*dkim.Verification
	err    error
}

type transactionCommitRecord struct {
	headerDigest   string
	bodyDigest     string
	signatureName  string
	signatureValue string
	report         string
}

var errTransactionAborted = errors.New("dkim-milter: message aborted")

func (s *session) Connect(host string, family string, port uint16, addr net.IP, m *milter.Modifier) (milter.Response, error) {
	s.mu.Lock()
	s.resetMessageLocked()
	s.mu.Unlock()
	return nil, nil
}

func (s *session) Helo(name string, m *milter.Modifier) (milter.Response, error) {
	s.mu.Lock()
	s.resetMessageLocked()
	s.mu.Unlock()
	return nil, nil
}

func (s *session) MailFrom(from string, m *milter.Modifier) (milter.Response, error) {
	s.mu.Lock()
	s.startMessageLocked()
	s.mu.Unlock()
	return nil, nil
}

func (s *session) RcptTo(rcptTo string, m *milter.Modifier) (milter.Response, error) {
	return nil, nil
}

func parseAddressDomain(s string) (string, error) {
	addr, err := mail.ParseAddress(s)
	if err != nil {
		return "", err
	}

	parts := strings.SplitN(addr.Address, "@", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("dkim-milter: malformed address: missing '@'")
	}

	return parts[1], nil
}

func (s *session) Header(name string, value string, m *milter.Modifier) (milter.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.shouldStartNewMessageLocked(name) {
		s.startMessageLocked()
	}

	if s.seen == nil {
		s.seen = make(map[string]bool)
	}
	s.headerNames = append(s.headerNames, name)
	s.seen[strings.ToLower(name)] = true

	if strings.EqualFold(name, "Message-ID") && s.messageID == "" {
		s.messageID = strings.TrimSpace(value)
	}

	if strings.EqualFold(name, "From") || strings.EqualFold(name, "Sender") {
		domain, err := parseAddressDomain(value)
		if err != nil {
			return nil, fmt.Errorf("dkim-milter: failed to parse header field '%v': %v", name, err)
		}

		for _, d := range signDomains {
			if strings.EqualFold(d, domain) {
				s.signDomain = d
				break
			}
		}
	}

	for _, k := range signHeaderKeys {
		if strings.EqualFold(name, k) {
			s.signHeaderKeys = append(s.signHeaderKeys, name)
		}
	}

	field := name + ": " + value + "\r\n"
	_, err := s.headerBuf.WriteString(field)
	return milter.RespContinue, err
}

func getIdentity(authRes string) string {
	parts := strings.SplitN(authRes, ";", 2)
	return strings.TrimSpace(parts[0])
}

func (s *session) Headers(h textproto.MIMEHeader, m *milter.Modifier) (milter.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		s.startMessageLocked()
	}
	if s.headersDone {
		// A second Headers callback without a new Header sequence is a new
		// (empty) message. Never reuse the previous message's snapshot.
		s.startMessageLocked()
	}

	// Write final CRLF to begin message body
	if _, err := s.headerBuf.WriteString("\r\n"); err != nil {
		return nil, err
	}

	headerBytes := append([]byte(nil), s.headerBuf.Bytes()...)
	sum := sha256.Sum256(headerBytes)
	s.headerDigest = hex.EncodeToString(sum[:])
	s.stage = "headers"

	if s.messageID == "" {
		for name, ids := range h {
			if strings.EqualFold(name, "Message-ID") && len(ids) > 0 {
				s.messageID = strings.TrimSpace(ids[0])
				break
			}
		}
	}

	// Delete any existing Authentication-Results header field with our
	// identity. textproto.MIMEHeader groups header fields by name, whereas
	// milter.ChangeHeader expects the field's position in the whole header
	// block. Resolve the absolute position from the received header sequence.
	fields := h["Authentication-Results"]
	if len(fields) == 0 {
		for name, values := range h {
			if strings.EqualFold(name, "Authentication-Results") {
				fields = values
				break
			}
		}
	}
	for i, field := range fields {
		if !strings.EqualFold(identity, getIdentity(field)) {
			continue
		}

		occurrence := i
		found := false
		for j, name := range s.headerNames {
			if !strings.EqualFold(name, "Authentication-Results") {
				continue
			}
			if occurrence == 0 {
				s.authResDelete = append(s.authResDelete, j)
				found = true
				break
			}
			occurrence--
		}
		if !found {
			// Preserve the historical behavior for callers which provide a
			// header map without the corresponding Header callbacks.
			s.authResDelete = append(s.authResDelete, i)
		}
	}

	// Sign if necessary
	if s.signDomain != "" {
		headerKeys := append([]string(nil), s.signHeaderKeys...)
		opts := dkim.SignOptions{
			Domain: s.signDomain,
			Selector: selector,
			Signer: privateKey,
			HeaderKeys: headerKeys,
			QueryMethods: []dkim.QueryMethod{dkim.QueryMethodDNSTXT},
		}

		var err error
		s.signer, err = dkim.NewSigner(&opts)
		if err != nil {
			s.stage = "signer-error"
			s.cancelMessageLocked()
			return nil, err
		}
	}

	// Verify existing signatures
	done := make(chan error, 1)
	outcome := make(chan transactionVerifyOutcome, 1)
	pr, pw := io.Pipe()

	s.done = done
	s.verifyDone = outcome
	s.pw = pw

	// TODO: limit max. number of signatures
	go func() {
		verifs, err := dkim.Verify(pr)
		io.Copy(ioutil.Discard, pr)
		pr.Close()
		outcome <- transactionVerifyOutcome{verifs: verifs, err: err}
		done <- err
		close(outcome)
		close(done)
	}()

	s.headersDone = true

	// Process header
	if err := s.writeChunkLocked(headerBytes, false); err != nil {
		s.stage = "header-write-error"
		s.cancelMessageLocked()
		return nil, err
	}
	return milter.RespContinue, nil
}

func (s *session) BodyChunk(chunk []byte, m *milter.Modifier) (milter.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active || !s.headersDone {
		return nil, fmt.Errorf("dkim-milter: body chunk received before message headers")
	}

	s.bodyStarted = true
	s.stage = "body"
	if err := s.writeChunkLocked(chunk, true); err != nil {
		s.stage = "body-write-error"
		s.cancelMessageLocked()
		return nil, err
	}
	return milter.RespContinue, nil
}

func (s *session) Body(m *milter.Modifier) (milter.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active || !s.headersDone {
		return nil, fmt.Errorf("dkim-milter: no message in progress")
	}
	if s.committed {
		return milter.RespAccept, nil
	}
	if s.bodyDone {
		return nil, fmt.Errorf("dkim-milter: message already finished")
	}
	s.bodyDone = true

	if s.pw == nil || s.verifyDone == nil {
		s.stage = "incomplete-state"
		s.cancelMessageLocked()
		return nil, fmt.Errorf("dkim-milter: message verification was not started")
	}

	if err := s.pw.Close(); err != nil {
		s.stage = "close-error"
		s.cancelMessageLocked()
		return nil, err
	}

	outcome := <-s.verifyDone
	s.verifs = outcome.verifs
	if outcome.err != nil {
		if verbose {
			log.Printf("DKIM verification failed: %v", outcome.err)
		}
		s.stage = "verify-error"
		s.cancelMessageLocked()
		return nil, outcome.err
	}

	bodyDigest := s.bodyDigestLocked()

	// A message ID is the identity of a transaction. Once a message has been
	// committed, a retry with the same identity must either replay the exact
	// same complete message or be rejected. Re-signing changed header/body
	// bytes under the old ID would let a sender replace the message while
	// keeping its audit identity.
	var committed *transactionCommitRecord
	if s.messageID != "" {
		if previous, ok := s.transactionCommitRecords[s.messageID]; ok {
			if previous.headerDigest != s.headerDigest || previous.bodyDigest != bodyDigest {
				s.stage = "message-id-conflict"
				s.cancelMessageLocked()
				return nil, fmt.Errorf("dkim-milter: message ID %q reused with different message content (header-sha256=%s body-sha256=%s stage=message-id-conflict)",
					s.messageID, s.headerDigest, bodyDigest)
			}

			committed = previous
			if s.signer != nil {
				s.signer.Cancel()
				s.signer = nil
			}
		}
	}

	var signatureName, signatureValue, report string
	if committed != nil {
		// Replay the complete result of the original transaction. This keeps
		// the signature, the report and the message ID bound to one immutable
		// snapshot even when an MTA retries an already committed message.
		signatureName = committed.signatureName
		signatureValue = committed.signatureValue
		report = committed.report
	} else {
		if s.signer != nil {
			if err := s.signer.Close(); err != nil {
				if verbose {
					log.Printf("DKIM signature failed: %v", err)
				}
				s.stage = "sign-error"
				s.cancelMessageLocked()
				return nil, err
			}
		}
		s.stage = "signed"

		if s.signer != nil {
			kv := s.signer.Signature()
			parts := strings.SplitN(kv, ": ", 2)
			if len(parts) != 2 {
				panic("dkim-milter: malformed DKIM-Signature header field")
			}
			signatureName = parts[0]
			signatureValue = strings.TrimSuffix(parts[1], "\r\n")
		}

		s.stage = "commit"
		report = msgauth.Format(identity, s.authResultsLocked())
		if s.messageID != "" {
			report += s.transactionEvidenceLocked()
		}
	}

	if err := s.commitLocked(m, signatureName, signatureValue, report); err != nil {
		return nil, err
	}

	if s.messageID != "" {
		if s.transactionCommitRecords == nil {
			s.transactionCommitRecords = make(map[string]*transactionCommitRecord)
		}
		s.transactionCommitRecords[s.messageID] = &transactionCommitRecord{
			headerDigest:   s.headerDigest,
			bodyDigest:     bodyDigest,
			signatureName:  signatureName,
			signatureValue: signatureValue,
			report:         report,
		}
	}

	if verbose {
		log.Printf("DKIM milter committed message %q (%s)", s.messageID, s.transactionEvidenceLocked())
	}

	return milter.RespAccept, nil
}

func (s *session) authResultsLocked() []msgauth.Result {
	results := make([]msgauth.Result, 0, len(s.verifs))

	if len(s.verifs) == 0 && s.signer == nil {
		results = append(results, &msgauth.DKIMResult{
			Value: msgauth.ResultNone,
		})
	}

	for _, verif := range s.verifs {
		if verbose {
			if verif.Err != nil {
				log.Printf("DKIM verification failed for %v: %v", verif.Domain, verif.Err)
			} else {
				log.Printf("DKIM verification succeded for %v", verif.Domain)
			}
		}

		var val msgauth.ResultValue
		if verif.Err == nil {
			val = msgauth.ResultPass
		} else if dkim.IsPermFail(verif.Err) {
			val = msgauth.ResultPermError
		} else if dkim.IsTempFail(verif.Err) {
			val = msgauth.ResultTempError
		} else {
			val = msgauth.ResultFail
		}

		results = append(results, &msgauth.DKIMResult{
			Value:      val,
			Domain:     verif.Domain,
			Identifier: verif.Identifier,
		})
	}

	return results
}

func (s *session) commitLocked(m *milter.Modifier, signatureName, signatureValue, report string) error {
	deleteIndices := append([]int(nil), s.authResDelete...)
	sort.Sort(sort.Reverse(sort.IntSlice(deleteIndices)))
	for _, index := range deleteIndices {
		if m == nil {
			continue
		}
		if err := m.ChangeHeader(index, "Authentication-Results", ""); err != nil {
			s.stage = "delete-report-error"
			s.cancelMessageLocked()
			return err
		}
	}

	if signatureName != "" && m != nil {
		if err := m.InsertHeader(0, signatureName, signatureValue); err != nil {
			s.stage = "insert-signature-error"
			s.cancelMessageLocked()
			return err
		}
	}

	if m != nil {
		if err := m.InsertHeader(0, "Authentication-Results", report); err != nil {
			s.stage = "insert-report-error"
			s.cancelMessageLocked()
			return err
		}
	}

	s.stage = "commit"
	s.committed = true
	return nil
}

// Abort discards the message currently being processed. Background
// verification and signing for that message are canceled before this function
// returns, so they cannot publish a result for a later message.
func (s *session) Abort() {
	s.mu.Lock()
	s.stage = "aborted"
	s.cancelMessageLocked()
	s.mu.Unlock()
}

// Close releases any resources associated with the session.
func (s *session) Close() error {
	s.Abort()
	return nil
}

// Reset discards all state for the current message. It is safe to call between
// messages or after an aborted transaction.
func (s *session) Reset() {
	s.mu.Lock()
	s.resetMessageLocked()
	s.transactionCommitRecords = nil
	s.mu.Unlock()
}

func (s *session) shouldStartNewMessageLocked(name string) bool {
	if !s.active {
		return true
	}
	if s.headersDone || s.bodyStarted || s.bodyDone || s.committed {
		return true
	}

	// A repeated single-instance header is the start of a retry. This also
	// catches clients which abort in the middle of a header block, before we
	// get a chance to see Headers.
	key := strings.ToLower(name)
	if s.seen[key] && isSingleInstanceHeader(key) {
		return true
	}
	return false
}

func isSingleInstanceHeader(key string) bool {
	switch key {
	case "from", "sender", "reply-to", "to", "cc", "bcc", "subject", "date",
		"message-id", "in-reply-to", "references":
		return true
	}
	return false
}

func (s *session) startMessageLocked() {
	s.resetMessageLocked()

	s.active = true
	s.generation++
	s.seen = make(map[string]bool)
	s.bodyHasher = sha256.New()
	s.stage = "admitted"
}

func (s *session) resetMessageLocked() {
	s.cancelMessageLocked()

	s.authResDelete = nil
	s.headerBuf.Reset()
	s.headerNames = nil
	s.signDomain = ""
	s.signHeaderKeys = nil
	s.verifs = nil
	s.active = false
	s.headersDone = false
	s.bodyStarted = false
	s.bodyDone = false
	s.committed = false
	s.messageID = ""
	s.seen = nil
	s.headerDigest = ""
	s.bodyHasher = nil
	s.bodyLen = 0
	s.stage = ""
}

func (s *session) cancelMessageLocked() {
	if s.pw != nil {
		s.pw.CloseWithError(errTransactionAborted)
		s.pw = nil
	}
	if s.signer != nil {
		s.signer.Cancel()
		s.signer = nil
	}

	s.done = nil
	s.verifyDone = nil
	s.verifs = nil
	s.active = false
}

func (s *session) writeChunkLocked(chunk []byte, isBody bool) error {
	if s.pw != nil {
		if _, err := s.pw.Write(chunk); err != nil {
			return err
		}
	}
	if s.signer != nil {
		if _, err := s.signer.Write(chunk); err != nil {
			return err
		}
	}
	if isBody {
		if s.bodyHasher != nil {
			if _, err := s.bodyHasher.Write(chunk); err != nil {
				return err
			}
		}
		s.bodyLen += int64(len(chunk))
	}
	return nil
}

func (s *session) transactionEvidenceLocked() string {
	messageID := s.messageID
	if messageID == "" {
		messageID = "none"
	} else {
		messageID = strings.Map(func(r rune) rune {
			switch r {
			case '(', ')', '\\', '\r', '\n', '\t':
				return '_'
			}
			return r
		}, messageID)
	}

	return fmt.Sprintf(" (dkim-milter generation=%d message-id=%s header-sha256=%s body-sha256=%s body-bytes=%d stage=%s)",
		s.generation, messageID, s.headerDigest, s.bodyDigestLocked(), s.bodyLen, s.stage)
}

func (s *session) bodyDigestLocked() string {
	if s.bodyHasher == nil {
		return ""
	}
	sum := s.bodyHasher.Sum(nil)
	return hex.EncodeToString(sum)
}

func loadPrivateKey(path string) (crypto.Signer, error) {
	f, err := os.Open(privateKeyPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	if err := f.Close(); err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM data found")
	}

	switch strings.ToUpper(block.Type) {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EDDSA PRIVATE KEY":
		if len(block.Bytes) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid Ed25519 private key size")
		}
		return ed25519.PrivateKey(block.Bytes), nil
	default:
		return nil, fmt.Errorf("unknown private key type: '%v'", block.Type)
	}
}

func main() {
	flag.Parse()

	if identity == "" {
		var err error
		identity, err = os.Hostname()
		if err != nil {
			log.Fatal("Failed to read hostname: ", err)
		}
	}

	if (len(signDomains) > 0 || privateKeyPath != "" || selector != "") && !(len(signDomains) > 0 && privateKeyPath != "" && selector != "") {
		log.Fatal("Domain(s) (-d) and private key (-k) must be both specified")
	}

	if privateKeyPath != "" {
		var err error
		privateKey, err = loadPrivateKey(privateKeyPath)
		if err != nil {
			log.Fatalf("Failed to load private key from '%v': %v", privateKeyPath, err)
		}
	}

	parts := strings.SplitN(listenURI, "://", 2)
	if len(parts) != 2 {
		log.Fatal("Invalid listen URI")
	}
	listenNetwork, listenAddr := parts[0], parts[1]

	s := milter.Server{
		NewMilter: func() milter.Milter {
			return &session{}
		},
		Actions:  milter.OptAddHeader | milter.OptChangeHeader,
		Protocol: milter.OptNoConnect | milter.OptNoHelo | milter.OptNoMailFrom | milter.OptNoRcptTo,
	}

	ln, err := net.Listen(listenNetwork, listenAddr)
	if err != nil {
		log.Fatal("Failed to setup listener: ", err)
	}

	// Closing the listener will unlink the unix socket, if any
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		if err := s.Close(); err != nil {
			log.Fatal("Failed to close server: ", err)
		}
	}()

	log.Println("Milter listening at", listenURI)
	if err := s.Serve(ln); err != nil && err != milter.ErrServerClosed {
		log.Fatal("Failed to serve: ", err)
	}
}
