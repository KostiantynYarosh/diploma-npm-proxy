package layer3

import (
	"regexp"
	"strings"
	"testing"
)

func TestStripComments_LineComment(t *testing.T) {
	src := `let x = 1; // do not use eval() in production
let y = 2;`
	out := stripComments(src)
	if strings.Contains(out, "eval(") {
		t.Errorf("line comment should be erased; got: %q", out)
	}
	if !strings.Contains(out, "let x = 1;") || !strings.Contains(out, "let y = 2;") {
		t.Errorf("real code lost: %q", out)
	}
}

func TestStripComments_BlockComment(t *testing.T) {
	src := "let x = 1; /* uses child_process when shelling out */ let y = 2;"
	out := stripComments(src)
	if strings.Contains(out, "child_process") {
		t.Errorf("block comment should be erased; got: %q", out)
	}
	if !strings.Contains(out, "let x = 1;") || !strings.Contains(out, "let y = 2;") {
		t.Errorf("real code lost: %q", out)
	}
}

func TestStripComments_PreservesStrings(t *testing.T) {
	src := `const m = require('child_process'); // dangerous`
	out := stripComments(src)
	if !strings.Contains(out, "require('child_process')") {
		t.Errorf("string literal in import should remain visible: %q", out)
	}
}

func TestStripComments_CommentInsideString(t *testing.T) {
	// // inside a string is NOT a comment.
	src := `const url = "http://example.com//path";`
	out := stripComments(src)
	if !strings.Contains(out, `"http://example.com//path"`) {
		t.Errorf("string content holding // must be preserved: %q", out)
	}
}

func TestStripStringContents_KillsCallInsideString(t *testing.T) {
	src := `const doc = "do not use eval() please";`
	out := stripStringContents(src)
	if regexp.MustCompile(`(?:^|[^.\w])eval\s*\(`).MatchString(out) {
		t.Errorf("eval( inside string should not match after stripping: %q", out)
	}
}

func TestStripStringContents_PreservesCodeCalls(t *testing.T) {
	src := `eval("payload"); new Function("p")();`
	out := stripStringContents(src)
	if !regexp.MustCompile(`(?:^|[^.\w])eval\s*\(`).MatchString(out) {
		t.Errorf("eval( call must still match: %q", out)
	}
	if !regexp.MustCompile(`new\s+Function\s*\(`).MatchString(out) {
		t.Errorf("new Function( must still match: %q", out)
	}
}

func TestStripStringContents_TemplateLiteral(t *testing.T) {
	src := "const greet = `hello eval(...) world`; eval('real');"
	out := stripStringContents(src)
	// First eval (inside template) gone; second (real call) preserved.
	matches := regexp.MustCompile(`(?:^|[^.\w])eval\s*\(`).FindAllStringIndex(out, -1)
	if len(matches) != 1 {
		t.Errorf("expected exactly one eval( match (real call only), got %d: %q", len(matches), out)
	}
}
