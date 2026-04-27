package signal

// Signal is a single detection result from any analysis layer.
type Signal struct {
	Rule           string  // machine-readable rule name
	Score          float64 // contribution to the aggregate risk score (0.0–1.0)
	Veto           bool    // if true, block immediately regardless of total score
	CWE            string  // optional CWE ID
	MatchedPackage string  // populated by typosquat/version-diff: the reference name this signal relates to
	Detail         string  // human-readable detail, e.g. "edit_distance=1" or "homoglyph_cyrillic"
}

// Result aggregates all signals produced across all layers for one request.
type Result struct {
	Signals []Signal
}

func (r *Result) Add(s Signal) {
	r.Signals = append(r.Signals, s)
}

func (r *Result) HasVeto() bool {
	for _, s := range r.Signals {
		if s.Veto {
			return true
		}
	}
	return false
}

func (r *Result) TotalScore() float64 {
	var total float64
	for _, s := range r.Signals {
		total += s.Score
	}
	if total > 1.0 {
		return 1.0
	}
	return total
}

func (r *Result) TriggeredRules() []string {
	rules := make([]string, 0, len(r.Signals))
	for _, s := range r.Signals {
		rules = append(rules, s.Rule)
	}
	return rules
}

func (r *Result) CWEIDs() []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range r.Signals {
		if s.CWE != "" {
			if _, ok := seen[s.CWE]; !ok {
				seen[s.CWE] = struct{}{}
				out = append(out, s.CWE)
			}
		}
	}
	return out
}
