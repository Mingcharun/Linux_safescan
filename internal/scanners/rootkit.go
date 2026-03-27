package scanners

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Mingcharun/Linux_safescan/internal/model"
	"github.com/Mingcharun/Linux_safescan/internal/rules"
	"github.com/Mingcharun/Linux_safescan/internal/scanner"
)

type rootkitScanner struct{}

// NewRootkitScanner creates the rootkit scanner.
func NewRootkitScanner() scanner.Runner { return &rootkitScanner{} }

func (s *rootkitScanner) Name() string { return "Rootkit Detection" }

func (s *rootkitScanner) Run(ctx context.Context, rt *scanner.Runtime) ([]model.Finding, error) {
	_ = ctx
	corpus, err := rules.LoadRootkits(rt.Options.RootkitSource)
	if err != nil {
		return nil, err
	}
	if corpus == nil || len(corpus.Rules) == 0 {
		return nil, nil
	}

	kallsyms := readKallsyms()
	findings := make([]model.Finding, 0)
	for _, rule := range corpus.Rules {
		if finding, ok := matchRootkitRule(rule, kallsyms); ok {
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      rule.Name,
				File:      finding.path,
				Info:      finding.info,
				Consult:   finding.consult,
				Severity:  model.SeverityRisk,
				Programme: finding.programme,
				CreatedAt: time.Now(),
			})
		}
	}

	findings = append(findings, scanBadLKMs(corpus.LKMNames)...)
	return findings, nil
}

type rootkitMatch struct {
	path      string
	info      string
	consult   string
	programme string
}

func matchRootkitRule(rule rules.RootkitRule, kallsyms []string) (rootkitMatch, bool) {
	for _, candidate := range rule.Files {
		if path, ok := resolveRootkitPattern(candidate); ok {
			return rootkitMatch{
				path:      path,
				info:      "Matched rootkit file rule: " + rule.Name + " -> " + path,
				consult:   "[1] strings " + path,
				programme: "rm " + path + " # remove rootkit artifact",
			}, true
		}
	}
	for _, candidate := range rule.Dirs {
		if path, ok := resolveRootkitPattern(candidate); ok {
			return rootkitMatch{
				path:      path,
				info:      "Matched rootkit directory rule: " + rule.Name + " -> " + path,
				consult:   "[1] ls -a " + path,
				programme: "rm -rf " + path + " # remove rootkit directory",
			}, true
		}
	}
	for _, token := range rule.KSyms {
		for _, line := range kallsyms {
			if strings.Contains(line, token) {
				return rootkitMatch{
					path:      "/proc/kallsyms",
					info:      "Matched kernel symbol indicative of " + rule.Name + ": " + token,
					consult:   "[1] cat /proc/kallsyms",
					programme: "",
				}, true
			}
		}
	}
	return rootkitMatch{}, false
}

func resolveRootkitPattern(pattern string) (string, bool) {
	if hasGlob(pattern) {
		matches, _ := filepath.Glob(pattern)
		slices.Sort(matches)
		for _, match := range matches {
			if _, err := os.Stat(match); err == nil {
				return match, true
			}
		}
		return "", false
	}
	if _, err := os.Stat(pattern); err == nil {
		return pattern, true
	}
	return "", false
}

func hasGlob(pattern string) bool {
	return strings.ContainsAny(pattern, "*?[")
}

func readKallsyms() []string {
	for _, file := range []string{"/proc/kallsyms", "/proc/ksyms"} {
		data, err := os.ReadFile(file)
		if err == nil {
			return strings.Split(string(data), "\n")
		}
	}
	return nil
}

func scanBadLKMs(badNames []string) []model.Finding {
	findings := make([]model.Finding, 0)
	_ = scanner.WalkFiles("/lib/modules", func(path string, info os.FileInfo) error {
		base := filepath.Base(path)
		if !strings.HasSuffix(base, ".so") && !strings.HasSuffix(base, ".ko") && !strings.HasSuffix(base, ".ko.xz") {
			return nil
		}
		for _, bad := range badNames {
			if base == bad {
				findings = append(findings, model.Finding{
					Category:  "Rootkit Detection",
					Name:      "LKM module check",
					File:      path,
					Info:      "Module matches known malicious LKM name: " + bad,
					Consult:   "[1] ls -l " + path + " [2] strings " + path,
					Severity:  model.SeverityRisk,
					Programme: "rm " + path + " # remove rootkit module",
					CreatedAt: time.Now(),
				})
				return nil
			}
		}
		return nil
	})
	return findings
}
