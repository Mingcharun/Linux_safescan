package rules

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

// YaraLiteCorpus is a light-weight evaluator for the bundled webshell rules.
type YaraLiteCorpus struct {
	Rules []YaraLiteRule
}

// YaraLiteRule captures a simplified YARA rule.
type YaraLiteRule struct {
	Name      string
	Patterns  map[string]YaraPattern
	Condition string
}

// YaraPattern evaluates a single YARA string entry.
type YaraPattern struct {
	ID       string
	Kind     string
	Text     string
	Regex    *regexp.Regexp
	Hex      []hexToken
	Wide     bool
	Fullword bool
}

type matchState struct {
	Matched bool
	AtZero  bool
}

type hexToken struct {
	Mask  byte
	Value byte
}

// LoadYaraLite reads `.yar` files from a directory.
func LoadYaraLite(dir string) (*YaraLiteCorpus, error) {
	out := &YaraLiteCorpus{Rules: []YaraLiteRule{}}
	if dir == "" {
		return out, nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, fmt.Errorf("stat webshell rules dir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("webshell rules path is not a directory: %s", dir)
	}

	files, err := filepath.Glob(filepath.Join(dir, "*.yar"))
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		out.Rules = append(out.Rules, parseYaraLiteRules(string(data))...)
	}
	return out, nil
}

// Match returns rule names that matched the given content.
func (c *YaraLiteCorpus) Match(data []byte) []string {
	if c == nil {
		return nil
	}
	matched := make([]string, 0)
	for _, rule := range c.Rules {
		if rule.Match(data) {
			matched = append(matched, rule.Name)
		}
	}
	return matched
}

// Match evaluates a single rule.
func (r YaraLiteRule) Match(data []byte) bool {
	if len(r.Patterns) == 0 {
		return false
	}
	states := make(map[string]matchState, len(r.Patterns))
	for id, pattern := range r.Patterns {
		states[id] = pattern.Match(data)
	}
	return evalYaraCondition(r.Condition, data, states)
}

// Match evaluates a single string/regex/hex pattern.
func (p YaraPattern) Match(data []byte) matchState {
	switch p.Kind {
	case "text":
		if p.Wide {
			wide := utf16le(p.Text)
			if bytes.HasPrefix(data, wide) {
				return matchState{Matched: true, AtZero: true}
			}
			if bytes.Contains(data, wide) {
				return matchState{Matched: true}
			}
		}
		raw := []byte(p.Text)
		if bytes.HasPrefix(data, raw) {
			return matchState{Matched: true, AtZero: true}
		}
		return matchState{Matched: bytes.Contains(data, raw)}
	case "regex":
		if p.Regex == nil {
			return matchState{}
		}
		loc := p.Regex.FindIndex(data)
		if len(loc) != 2 {
			return matchState{}
		}
		return matchState{Matched: true, AtZero: loc[0] == 0}
	case "hex":
		if len(p.Hex) == 0 {
			return matchState{}
		}
		atZero := hexMatchAt(data, p.Hex, 0)
		if atZero {
			return matchState{Matched: true, AtZero: true}
		}
		for i := 1; i+len(p.Hex) <= len(data); i++ {
			if hexMatchAt(data, p.Hex, i) {
				return matchState{Matched: true}
			}
		}
	}
	return matchState{}
}

func parseYaraLiteRules(content string) []YaraLiteRule {
	rulesOut := make([]YaraLiteRule, 0, 16)
	lines := strings.Split(content, "\n")

	var block strings.Builder
	inRule := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !inRule && strings.HasPrefix(trimmed, "rule ") {
			inRule = true
		}
		if !inRule {
			continue
		}
		block.WriteString(line)
		block.WriteString("\n")
		if inRule && trimmed == "}" {
			if rule, ok := parseYaraLiteRule(block.String()); ok {
				rulesOut = append(rulesOut, rule)
			}
			block.Reset()
			inRule = false
		}
	}
	return rulesOut
}

func parseYaraLiteRule(block string) (YaraLiteRule, bool) {
	head := regexp.MustCompile(`rule\s+([A-Za-z0-9_]+)`).FindStringSubmatch(block)
	if len(head) != 2 {
		return YaraLiteRule{}, false
	}
	stringsIndex := strings.Index(block, "strings:")
	conditionIndex := strings.Index(block, "condition:")
	if conditionIndex == -1 {
		return YaraLiteRule{}, false
	}
	var stringsSection string
	if stringsIndex != -1 && stringsIndex < conditionIndex {
		stringsSection = block[stringsIndex+len("strings:") : conditionIndex]
	}
	conditionSection := strings.TrimSpace(block[conditionIndex+len("condition:"):])
	conditionSection = strings.TrimSpace(strings.TrimSuffix(conditionSection, "}"))

	patterns := make(map[string]YaraPattern)
	for _, line := range strings.Split(stringsSection, "\n") {
		if pattern, ok := parseYaraPattern(line); ok {
			patterns[pattern.ID] = pattern
		}
	}

	return YaraLiteRule{
		Name:      head[1],
		Patterns:  patterns,
		Condition: normalizeCondition(conditionSection),
	}, true
}

func parseYaraPattern(line string) (YaraPattern, bool) {
	line = strings.TrimSpace(line)
	if line == "" || !strings.HasPrefix(line, "$") || !strings.Contains(line, "=") {
		return YaraPattern{}, false
	}
	if idx := strings.Index(line, "/*"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return YaraPattern{}, false
	}
	id := strings.TrimSpace(strings.TrimPrefix(parts[0], "$"))
	body := strings.TrimSpace(parts[1])
	pattern := YaraPattern{ID: id}

	if strings.HasPrefix(body, "\"") {
		last := strings.LastIndex(body, "\"")
		if last <= 0 {
			return YaraPattern{}, false
		}
		value, err := strconv.Unquote(body[:last+1])
		if err != nil {
			return YaraPattern{}, false
		}
		pattern.Kind = "text"
		pattern.Text = value
		pattern.Wide = strings.Contains(body[last+1:], "wide")
		pattern.Fullword = strings.Contains(body[last+1:], "fullword")
		return pattern, true
	}
	if strings.HasPrefix(body, "/") {
		last := strings.LastIndex(body, "/")
		if last <= 0 {
			return YaraPattern{}, false
		}
		raw := body[1:last]
		expr, err := regexp.Compile(raw)
		if err != nil {
			return YaraPattern{}, false
		}
		pattern.Kind = "regex"
		pattern.Regex = expr
		return pattern, true
	}
	if strings.HasPrefix(body, "{") {
		last := strings.LastIndex(body, "}")
		if last <= 0 {
			return YaraPattern{}, false
		}
		pattern.Kind = "hex"
		pattern.Hex = parseHexPattern(body[1:last])
		return pattern, true
	}
	return YaraPattern{}, false
}

func parseHexPattern(raw string) []hexToken {
	fields := strings.Fields(raw)
	out := make([]hexToken, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		switch {
		case field == "??":
			out = append(out, hexToken{Mask: 0x00, Value: 0x00})
		case len(field) == 2 && strings.HasSuffix(field, "?"):
			n, err := strconv.ParseUint(field[:1], 16, 8)
			if err == nil {
				out = append(out, hexToken{Mask: 0xF0, Value: byte(n << 4)})
			}
		case len(field) == 2 && strings.HasPrefix(field, "?"):
			n, err := strconv.ParseUint(field[1:], 16, 8)
			if err == nil {
				out = append(out, hexToken{Mask: 0x0F, Value: byte(n)})
			}
		default:
			n, err := strconv.ParseUint(field, 16, 8)
			if err == nil {
				out = append(out, hexToken{Mask: 0xFF, Value: byte(n)})
			}
		}
	}
	return out
}

func hexMatchAt(data []byte, pattern []hexToken, offset int) bool {
	if offset+len(pattern) > len(data) {
		return false
	}
	for i, token := range pattern {
		if token.Mask == 0 {
			continue
		}
		if data[offset+i]&token.Mask != token.Value {
			return false
		}
	}
	return true
}

func utf16le(s string) []byte {
	codepoints := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(codepoints)*2)
	for _, cp := range codepoints {
		out = append(out, byte(cp), byte(cp>>8))
	}
	return out
}

func normalizeCondition(cond string) string {
	cond = regexp.MustCompile(`\s+`).ReplaceAllString(strings.TrimSpace(cond), " ")
	return strings.TrimSpace(cond)
}

func evalYaraCondition(expr string, data []byte, states map[string]matchState) bool {
	expr = strings.TrimSpace(expr)
	for {
		if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") && balancedParens(expr[1:len(expr)-1]) {
			expr = strings.TrimSpace(expr[1 : len(expr)-1])
			continue
		}
		break
	}

	if parts := splitTopLevel(expr, " or "); len(parts) > 1 {
		for _, part := range parts {
			if evalYaraCondition(part, data, states) {
				return true
			}
		}
		return false
	}
	if parts := splitTopLevel(expr, " and "); len(parts) > 1 {
		for _, part := range parts {
			if !evalYaraCondition(part, data, states) {
				return false
			}
		}
		return true
	}
	return evalYaraAtom(expr, data, states)
}

func evalYaraAtom(expr string, data []byte, states map[string]matchState) bool {
	expr = strings.TrimSpace(expr)
	switch {
	case regexp.MustCompile(`^filesize\s*<\s*\d+(KB)?$`).MatchString(expr):
		size, unit := parseSizeBound(expr)
		if unit == "KB" {
			size *= 1024
		}
		return int64(len(data)) < size
	case regexp.MustCompile(`^filesize\s*>\s*\d+(KB)?$`).MatchString(expr):
		size, unit := parseSizeBound(expr)
		if unit == "KB" {
			size *= 1024
		}
		return int64(len(data)) > size
	case regexp.MustCompile(`^uint16\(0\)\s*==\s*0x[0-9a-fA-F]+$`).MatchString(expr):
		if len(data) < 2 {
			return false
		}
		raw := regexp.MustCompile(`0x([0-9a-fA-F]+)$`).FindStringSubmatch(expr)
		if len(raw) != 2 {
			return false
		}
		want, err := strconv.ParseUint(raw[1], 16, 16)
		if err != nil {
			return false
		}
		got := uint16(data[0]) | uint16(data[1])<<8
		return got == uint16(want)
	case expr == "all of them":
		return countMatches(states, func(string) bool { return true }) == len(states)
	case regexp.MustCompile(`^\d+\s+of them$`).MatchString(expr):
		n, _ := strconv.Atoi(strings.Fields(expr)[0])
		return countMatches(states, func(string) bool { return true }) >= n
	case regexp.MustCompile(`^all of \(\$[A-Za-z0-9_]+\*\)$`).MatchString(expr):
		prefix := regexp.MustCompile(`\(\$([A-Za-z0-9_]+)\*\)`).FindStringSubmatch(expr)[1]
		return countMatches(states, func(id string) bool { return strings.HasPrefix(id, prefix) }) == countEligible(states, func(id string) bool { return strings.HasPrefix(id, prefix) })
	case regexp.MustCompile(`^\d+\s+of \(\$[A-Za-z0-9_]+\*\)$`).MatchString(expr):
		n, _ := strconv.Atoi(strings.Fields(expr)[0])
		prefix := regexp.MustCompile(`\(\$([A-Za-z0-9_]+)\*\)`).FindStringSubmatch(expr)[1]
		return countMatches(states, func(id string) bool { return strings.HasPrefix(id, prefix) }) >= n
	case regexp.MustCompile(`^\$[A-Za-z0-9_]+\s+at\s+0$`).MatchString(expr):
		id := strings.TrimPrefix(strings.Fields(expr)[0], "$")
		state, ok := states[id]
		return ok && state.Matched && state.AtZero
	case regexp.MustCompile(`^\$[A-Za-z0-9_]+$`).MatchString(expr):
		id := strings.TrimPrefix(expr, "$")
		state, ok := states[id]
		return ok && state.Matched
	default:
		return false
	}
}

func parseSizeBound(expr string) (int64, string) {
	match := regexp.MustCompile(`(\d+)(KB)?`).FindStringSubmatch(expr)
	if len(match) < 2 {
		return 0, ""
	}
	value, _ := strconv.ParseInt(match[1], 10, 64)
	if len(match) == 3 {
		return value, match[2]
	}
	return value, ""
}

func countMatches(states map[string]matchState, allow func(string) bool) int {
	count := 0
	for id, state := range states {
		if allow(id) && state.Matched {
			count++
		}
	}
	return count
}

func countEligible(states map[string]matchState, allow func(string) bool) int {
	count := 0
	for id := range states {
		if allow(id) {
			count++
		}
	}
	return count
}

func splitTopLevel(expr string, sep string) []string {
	parts := make([]string, 0, 4)
	depth := 0
	last := 0
	for i := 0; i < len(expr); i++ {
		switch expr[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		}
		if depth == 0 && i+len(sep) <= len(expr) && strings.EqualFold(expr[i:i+len(sep)], sep) {
			parts = append(parts, strings.TrimSpace(expr[last:i]))
			last = i + len(sep)
			i += len(sep) - 1
		}
	}
	if last == 0 {
		return []string{expr}
	}
	parts = append(parts, strings.TrimSpace(expr[last:]))
	return parts
}

func balancedParens(expr string) bool {
	depth := 0
	for _, ch := range expr {
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}
