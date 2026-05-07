package layer3

import "strings"

// stripComments returns src with single-line (//) and multi-line (/* */)
// comments replaced by spaces. Newlines inside multi-line comments are kept
// so subsequent line/column counting is unaffected. String and template
// literals are not touched - import-shape patterns like require('child_process')
// must still see their literal content.
//
// This is a pragmatic substitute for proper AST analysis: it kills the
// dominant false-match source (identifiers in docstrings/comments) without
// the cost of pulling in a JS parser. Regex literals and JSX are not handled;
// they're not a measurable false-match source on the npm corpus we calibrate
// against.
func stripComments(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	i, n := 0, len(src)
	for i < n {
		c := src[i]
		switch {
		case c == '/' && i+1 < n && src[i+1] == '/':
			b.WriteByte(' ')
			b.WriteByte(' ')
			i += 2
			for i < n && src[i] != '\n' {
				b.WriteByte(' ')
				i++
			}
		case c == '/' && i+1 < n && src[i+1] == '*':
			b.WriteByte(' ')
			b.WriteByte(' ')
			i += 2
			for i < n {
				if i+1 < n && src[i] == '*' && src[i+1] == '/' {
					b.WriteByte(' ')
					b.WriteByte(' ')
					i += 2
					break
				}
				if src[i] == '\n' {
					b.WriteByte('\n')
				} else {
					b.WriteByte(' ')
				}
				i++
			}
		case c == '\'' || c == '"':
			// Copy whole single/double-quoted string verbatim; comments inside
			// strings are not comments.
			quote := c
			b.WriteByte(quote)
			i++
			for i < n {
				if src[i] == '\\' && i+1 < n {
					b.WriteByte(src[i])
					b.WriteByte(src[i+1])
					i += 2
					continue
				}
				if src[i] == '\n' {
					// Unterminated string - bail; treat as ended.
					break
				}
				b.WriteByte(src[i])
				if src[i] == quote {
					i++
					break
				}
				i++
			}
		case c == '`':
			// Template literal: copy verbatim to end-backtick; ignore ${...}
			// nesting (rare and tolerable for our purposes).
			b.WriteByte('`')
			i++
			for i < n {
				if src[i] == '\\' && i+1 < n {
					b.WriteByte(src[i])
					b.WriteByte(src[i+1])
					i += 2
					continue
				}
				b.WriteByte(src[i])
				if src[i] == '`' {
					i++
					break
				}
				i++
			}
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// stripStringContents returns src with the bodies of string and template
// literals replaced by spaces, preserving the surrounding quote characters
// and the original byte offsets. Apply on top of stripComments before regex
// scans for call patterns ("eval(", "new Function(") so that occurrences
// inside docstrings or log messages are no longer matched.
//
// Import-shape patterns must NOT use this function - they need the literal
// content (e.g. 'child_process') to be visible in the source.
func stripStringContents(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	i, n := 0, len(src)
	for i < n {
		c := src[i]
		if c == '\'' || c == '"' {
			quote := c
			b.WriteByte(quote)
			i++
			for i < n && src[i] != quote {
				if src[i] == '\\' && i+1 < n {
					b.WriteByte(' ')
					b.WriteByte(' ')
					i += 2
					continue
				}
				if src[i] == '\n' {
					break
				}
				b.WriteByte(' ')
				i++
			}
			if i < n && src[i] == quote {
				b.WriteByte(quote)
				i++
			}
			continue
		}
		if c == '`' {
			b.WriteByte('`')
			i++
			for i < n && src[i] != '`' {
				if src[i] == '\\' && i+1 < n {
					b.WriteByte(' ')
					b.WriteByte(' ')
					i += 2
					continue
				}
				if src[i] == '\n' {
					b.WriteByte('\n')
				} else {
					b.WriteByte(' ')
				}
				i++
			}
			if i < n {
				b.WriteByte('`')
				i++
			}
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String()
}
