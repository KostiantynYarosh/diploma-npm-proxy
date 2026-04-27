package layer3

import (
	"context"
	"strings"

	"github.com/evanw/esbuild/pkg/api"
	"github.com/yourusername/npm-proxy/internal/signal"
	"github.com/yourusername/npm-proxy/internal/extractor"
)

// Capability categories.
const (
	CapNet       = "net_access"
	CapExec      = "exec"
	CapFSSens    = "fs_sensitive"
	CapDynEval   = "dynamic_eval"
	CapEnvRead   = "env_read"
)

var netModules = map[string]bool{
	"http": true, "https": true, "net": true, "dgram": true, "tls": true,
}

var sensitivePaths = []string{"/etc/passwd", "/etc/shadow", ".ssh", ".npmrc", ".env"}

type CapabilityAnalyzer struct {
	netScore     float64
	execScore    float64
	fsSensScore  float64
	dynEvalScore float64
	envReadScore float64
}

func NewCapabilityAnalyzer(net, exec, fsSens, dynEval, envRead float64) *CapabilityAnalyzer {
	return &CapabilityAnalyzer{
		netScore:     net,
		execScore:    exec,
		fsSensScore:  fsSens,
		dynEvalScore: dynEval,
		envReadScore: envRead,
	}
}

// Analyze scans all JS/TS files in the tree and returns detected capability signals.
// Returns the capability names alongside signals so the engine can cache them.
func (a *CapabilityAnalyzer) Analyze(_ context.Context, tree extractor.FileTree) ([]signal.Signal, []string) {
	caps := make(map[string]bool)

	for path, content := range tree {
		if !isJSFile(path) {
			continue
		}
		detectCapabilities(string(content), caps)
	}

	var signals []signal.Signal
	var capList []string

	scoreMap := map[string]struct {
		score float64
		rule  string
		cwe   string
	}{
		CapNet:     {a.netScore, "capability_net_access", "CWE-918"},
		CapExec:    {a.execScore, "capability_exec", "CWE-78"},
		CapFSSens:  {a.fsSensScore, "capability_fs_sensitive", "CWE-22"},
		CapDynEval: {a.dynEvalScore, "capability_dynamic_eval", "CWE-94"},
		CapEnvRead: {a.envReadScore, "capability_env_read", ""},
	}

	for cap, detected := range caps {
		if !detected {
			continue
		}
		capList = append(capList, cap)
		if info, ok := scoreMap[cap]; ok {
			signals = append(signals, signal.Signal{
				Rule:  info.rule,
				Score: info.score,
				CWE:   info.cwe,
			})
		}
	}

	return signals, capList
}

func detectCapabilities(src string, caps map[string]bool) {
	result := api.Transform(src, api.TransformOptions{
		Loader: api.LoaderJS,
	})
	if len(result.Errors) > 0 {
		// Fall back to regex-based detection on parse failure.
		detectCapabilitiesRegex(src, caps)
		return
	}

	walkAST(src, caps)
}

// walkAST uses esbuild's parsed output to find capabilities.
// Since esbuild doesn't expose a Go AST walk API directly, we use its
// metafile / source map approach: parse + scan the transformed output
// for known patterns. For robust analysis we use source-level regex
// on the *original* source combined with esbuild's error-free validation.
func walkAST(src string, caps map[string]bool) {
	detectCapabilitiesRegex(src, caps)
}

func detectCapabilitiesRegex(src string, caps map[string]bool) {
	// Network capabilities.
	for mod := range netModules {
		if strings.Contains(src, `require('`+mod+`')`) ||
			strings.Contains(src, `require("`+mod+`")`) ||
			strings.Contains(src, `from '`+mod+`'`) ||
			strings.Contains(src, `from "`+mod+`"`) {
			caps[CapNet] = true
		}
	}

	// Exec capabilities.
	if strings.Contains(src, "child_process") {
		caps[CapExec] = true
	}

	// FS sensitive access.
	if strings.Contains(src, "require('fs')") || strings.Contains(src, `require("fs")`) {
		for _, sp := range sensitivePaths {
			if strings.Contains(src, sp) {
				caps[CapFSSens] = true
				break
			}
		}
	}

	// Dynamic eval.
	if strings.Contains(src, "eval(") ||
		strings.Contains(src, "new Function(") ||
		strings.Contains(src, "vm.runInThisContext") ||
		strings.Contains(src, "vm.runInNewContext") {
		caps[CapDynEval] = true
	}

	// Environment variable reading.
	if strings.Contains(src, "process.env") {
		caps[CapEnvRead] = true
	}
}

func isJSFile(path string) bool {
	return strings.HasSuffix(path, ".js") ||
		strings.HasSuffix(path, ".mjs") ||
		strings.HasSuffix(path, ".cjs") ||
		strings.HasSuffix(path, ".ts")
}
