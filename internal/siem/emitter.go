package siem

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type EventType string

const (
	EventPackageVerdict    EventType = "package_verdict"
	EventUpstreamDown      EventType = "upstream_down"
	EventAnalysisTimeout   EventType = "analysis_timeout"
	EventIntegrityMismatch EventType = "integrity_mismatch"
	EventResourceLimit     EventType = "resource_limit_exceeded"
	EventOSVMatch          EventType = "osv_match"
	EventMaliciousScript   EventType = "malicious_install_script"
)

type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictWarn  Verdict = "warn"
	VerdictBlock Verdict = "block"
)

type Event struct {
	EventType          EventType `json:"event_type"`
	Timestamp          time.Time `json:"timestamp"`
	PackageName        string    `json:"package_name"`
	PackageVersion     string    `json:"package_version"`
	SHA256             string    `json:"sha256,omitempty"`
	Verdict            Verdict   `json:"verdict,omitempty"`
	RiskScore          float64   `json:"risk_score,omitempty"`
	TriggeredRules     []string  `json:"triggered_rules,omitempty"`
	CWEIDs             []string  `json:"cwe_ids,omitempty"`
	ResponseCode       int       `json:"response_code,omitempty"`
	AnalysisDurationMs int64     `json:"analysis_duration_ms,omitempty"`
	SourceIP           string    `json:"source_ip,omitempty"`
}

// syslogWriter is the subset of *syslog.Writer we need.
// Defined here so platform-specific files can implement it.
type syslogWriter interface {
	Warning(m string) error
	Close() error
}

type Emitter interface {
	Emit(ctx context.Context, event Event) error
	Close()
}

type multiEmitter struct {
	emitters []Emitter
	ch       chan Event
}

func New(mode, syslogAddr, syslogNetwork, webhookURL, webhookSecret string, bufSize int) Emitter {
	var emitters []Emitter

	if (mode == "syslog" || mode == "both") && syslogAddr != "" {
		if w, err := dialSyslog(syslogNetwork, syslogAddr); err == nil {
			emitters = append(emitters, &syslogEmitter{w: w})
		} else {
			log.Printf("siem: syslog init failed: %v", err)
		}
	}

	if (mode == "webhook" || mode == "both") && webhookURL != "" {
		emitters = append(emitters, newWebhookEmitter(webhookURL, webhookSecret))
	}

	if len(emitters) == 0 {
		emitters = append(emitters, &logEmitter{})
	}

	m := &multiEmitter{
		emitters: emitters,
		ch:       make(chan Event, bufSize),
	}
	go m.run()
	return m
}

func (m *multiEmitter) Emit(_ context.Context, e Event) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	select {
	case m.ch <- e:
	default:
		log.Printf("siem: buffer full, dropping event %s/%s", e.PackageName, e.PackageVersion)
	}
	return nil
}

func (m *multiEmitter) Close() {
	close(m.ch)
}

func (m *multiEmitter) run() {
	for e := range m.ch {
		for _, em := range m.emitters {
			if err := em.Emit(context.Background(), e); err != nil {
				log.Printf("siem: delivery failed: %v", err)
			}
		}
	}
}

// syslog emitter

type syslogEmitter struct {
	w syslogWriter
}

func (s *syslogEmitter) Emit(_ context.Context, e Event) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return s.w.Warning(string(b))
}

func (s *syslogEmitter) Close() { _ = s.w.Close() }

// webhook emitter

type webhookEmitter struct {
	url    string
	secret string
	client *http.Client
}

func newWebhookEmitter(url, secret string) *webhookEmitter {
	return &webhookEmitter{
		url:    url,
		secret: secret,
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

func (w *webhookEmitter) Emit(ctx context.Context, e Event) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	if w.secret != "" {
		mac := hmac.New(sha256.New, []byte(w.secret))
		mac.Write(b)
		req.Header.Set("X-Signature-SHA256", hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}

func (w *webhookEmitter) Close() {}

// fallback stderr emitter

type logEmitter struct{}

func (l *logEmitter) Emit(_ context.Context, e Event) error {
	b, _ := json.Marshal(e)
	log.Printf("siem: %s", string(b))
	return nil
}

func (l *logEmitter) Close() {}
