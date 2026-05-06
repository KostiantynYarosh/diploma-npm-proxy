package policy

import (
	"testing"

	"github.com/yourusername/npm-proxy/internal/signal"
)

func TestPolicy_VetoBlocks(t *testing.T) {
	e := NewEngine(0.30, 0.70, 0)
	r := &signal.Result{}
	r.Add(signal.Signal{Rule: "osv_known_vulnerability", Veto: true})
	d := e.Decide(r)
	if d.Verdict != VerdictBlock || d.VetoRule != "osv_known_vulnerability" {
		t.Errorf("expected block via veto, got %+v", d)
	}
}

func TestPolicy_HighScoreBlocks(t *testing.T) {
	e := NewEngine(0.30, 0.70, 0)
	r := &signal.Result{}
	r.Add(signal.Signal{Rule: "a", Score: 0.5})
	r.Add(signal.Signal{Rule: "b", Score: 0.3})
	d := e.Decide(r)
	if d.Verdict != VerdictBlock {
		t.Errorf("expected block at score=0.8, got %+v", d)
	}
}

func TestPolicy_ModerateScoreWarns(t *testing.T) {
	e := NewEngine(0.30, 0.70, 0)
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
	e := NewEngine(0.30, 0.70, 0)
	r := &signal.Result{}
	r.Add(signal.Signal{Rule: "a", Score: 0.1})
	d := e.Decide(r)
	if d.Verdict != VerdictAllow {
		t.Errorf("expected allow at score=0.1, got %+v", d)
	}
}

func TestPolicy_NoSignalsAllows(t *testing.T) {
	e := NewEngine(0.30, 0.70, 0)
	d := e.Decide(&signal.Result{})
	if d.Verdict != VerdictAllow || d.Score != 0 {
		t.Errorf("expected allow with 0 score, got %+v", d)
	}
}

func TestPolicy_MultiCategoryGatingDowngradesToAllow(t *testing.T) {
	// Score crosses warn threshold but everything is in one category
	// (capability_*). With min_categories=2 the verdict must drop to allow.
	e := NewEngine(0.30, 0.70, 2)
	r := &signal.Result{}
	r.Add(signal.Signal{Rule: "cap_exec", Score: 0.30})
	r.Add(signal.Signal{Rule: "cap_net", Score: 0.20})
	d := e.Decide(r)
	if d.Verdict != VerdictAllow {
		t.Errorf("single-category 0.50 must allow under gating, got %+v", d)
	}
}

func TestPolicy_BlockThresholdBypassesMultiCategoryGating(t *testing.T) {
	// Gate protects the warning band only. Once score crosses block threshold,
	// even single-category evidence blocks.
	e := NewEngine(0.30, 0.70, 3)
	r := &signal.Result{}
	r.Add(signal.Signal{Rule: "install_script_child_process_preinstall", Score: 0.50})
	r.Add(signal.Signal{Rule: "install_script_node_eval_preinstall", Score: 0.50})
	d := e.Decide(r)
	if d.Verdict != VerdictBlock {
		t.Errorf("block-threshold score must bypass gating, got %+v", d)
	}
}

func TestPolicy_ComboSignalsCountAsIndependentCategory(t *testing.T) {
	e := NewEngine(0.30, 0.70, 2)
	r := &signal.Result{}
	r.Add(signal.Signal{Rule: "install_script_present", Score: 0.20})
	r.Add(signal.Signal{Rule: "install_script_with_exec", Score: 0.20})
	d := e.Decide(r)
	if d.Verdict != VerdictWarn {
		t.Errorf("install+combo should satisfy min_categories=2, got %+v", d)
	}
}

func TestPolicy_MultiCategoryGatingPassesWithDiverseRules(t *testing.T) {
	// Same total score but spread across two categories: warn must surface.
	e := NewEngine(0.30, 0.70, 2)
	r := &signal.Result{}
	r.Add(signal.Signal{Rule: "cap_exec", Score: 0.30})
	r.Add(signal.Signal{Rule: "install_script_present", Score: 0.20})
	d := e.Decide(r)
	if d.Verdict != VerdictWarn {
		t.Errorf("two-category 0.50 must warn under gating, got %+v", d)
	}
}

func TestPolicy_VetoIgnoresGating(t *testing.T) {
	// Veto must still block even with min_categories=99.
	e := NewEngine(0.30, 0.70, 99)
	r := &signal.Result{}
	r.Add(signal.Signal{Rule: "install_script_curl_pipe", Veto: true})
	d := e.Decide(r)
	if d.Verdict != VerdictBlock {
		t.Errorf("veto must bypass gating, got %+v", d)
	}
}
