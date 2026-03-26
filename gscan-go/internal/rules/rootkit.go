package rules

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// RootkitRule models one rootkit signature bundle.
type RootkitRule struct {
	Name  string
	Files []string
	Dirs  []string
	KSyms []string
}

// RootkitCorpus holds parsed rootkit rules and suspicious LKM names.
type RootkitCorpus struct {
	Rules    []RootkitRule
	LKMNames []string
}

// LoadRootkits parses the original Python Rootkit_Analysis.py definitions.
func LoadRootkits(path string) (*RootkitCorpus, error) {
	out := &RootkitCorpus{
		Rules:    []RootkitRule{},
		LKMNames: []string{},
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, fmt.Errorf("read rootkit source: %w", err)
	}
	content := string(data)

	blocks := extractPythonDictBlocks(content)
	for _, block := range blocks {
		rule := RootkitRule{
			Name:  extractSingleQuotedField(block, "name"),
			Files: extractQuotedListField(block, "file"),
			Dirs:  extractQuotedListField(block, "dir"),
			KSyms: extractQuotedListField(block, "ksyms"),
		}
		if rule.Name == "" {
			continue
		}
		out.Rules = append(out.Rules, rule)
	}

	lkmBlock := regexp.MustCompile(`(?s)self\.LKM_BADNAMES\s*=\s*\[(.*?)\]`).FindStringSubmatch(content)
	if len(lkmBlock) == 2 {
		out.LKMNames = extractQuotedValues(lkmBlock[1])
	}
	return out, nil
}

func extractPythonDictBlocks(content string) []string {
	lines := strings.Split(content, "\n")
	blocks := make([]string, 0, 128)
	var current strings.Builder
	depth := 0
	capturing := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !capturing && strings.Contains(trimmed, "= {") {
			capturing = true
		}
		if !capturing {
			continue
		}

		current.WriteString(line)
		current.WriteString("\n")
		depth += strings.Count(line, "{")
		depth -= strings.Count(line, "}")

		if capturing && depth == 0 {
			blocks = append(blocks, current.String())
			current.Reset()
			capturing = false
		}
	}

	return blocks
}

func extractSingleQuotedField(block string, field string) string {
	re := regexp.MustCompile(fmt.Sprintf(`'%s'\s*:\s*'([^']*)'`, regexp.QuoteMeta(field)))
	match := re.FindStringSubmatch(block)
	if len(match) != 2 {
		return ""
	}
	return match[1]
}

func extractQuotedListField(block string, field string) []string {
	re := regexp.MustCompile(fmt.Sprintf(`(?s)'%s'\s*:\s*\[(.*?)\]`, regexp.QuoteMeta(field)))
	match := re.FindStringSubmatch(block)
	if len(match) != 2 {
		return nil
	}
	return extractQuotedValues(match[1])
}

func extractQuotedValues(content string) []string {
	re := regexp.MustCompile(`'([^']*)'`)
	matches := re.FindAllStringSubmatch(content, -1)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) == 2 {
			out = append(out, match[1])
		}
	}
	return out
}
