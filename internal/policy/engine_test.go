package policy

import (
	"testing"

	"github.com/yourusername/npm-proxy/internal/signal"
)

func TestPolicy_VetoBlocks(t *testing.T) {
	e := NewEngine(0.30, 0.70)
	r := &signal.Result{}
	r.Add(signal.Signal{Rule: "osv_known_vulnerability", Veto: true})
	d := e.Decide(r)
	if d.Verdict != VerdictBlock || d.VetoRule != "osv_known_vulnerability" {
		t.Errorf("expected block via veto, got %+v", d)
	}
}

func TestPolicy_HighScoreBlocks(t *testing.T) {
	e := NewEngine(0.30, 0.70)
	r := &signal.Result{}
	r.Add(signal.Signal{Rule: "a", Score: 0.5})
	r.Add(signal.Signal{Rule: "b", Score: 0.3})
	d := e.Decide(r)
	if d.Verdict != VerdictBlock {
		t.Errorf("expected block at score=0.8, got %+v", d)
	}
}

func TestPolicy_ModerateScoreWarns(t *testing.T) {
	e := NewEngine(0.30, 0.70)
	r := &signal.Result{}
	r.Add(signal.Signal{Rule: "a", Score: 0.4})
	d := e.Decide(r)
	if d.Verdict != VerdictWarn {
		t.Errorf("expected warn at score=0.4, got %+v", d)
	}
	if d.WarningHeader == "" {
		t.Errorf("warn decision must carry a warning header")
	}
}

func TestPolicy_LowScoreAllows(t *testing.T) {
	e := NewEngine(0.30, 0.70)
	r := &signal.Result{}
	r.Add(signal.Signal{Rule: "a", Score: 0.1})
	d := e.Decide(r)
	if d.Verdict != VerdictAllow {
		t.Errorf("expected allow at score=0.1, got %+v", d)
	}
}

func TestPolicy_NoSignalsAllows(t *testing.T) {
	e := NewEngine(0.30, 0.70)
	d := e.Decide(&signal.Result{})
	if d.Verdict != VerdictAllow || d.Score != 0 {
		t.Errorf("expected allow with 0 score, got %+v", d)
	}
}
