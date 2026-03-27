package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Mingcharun/Linux_safescan/internal/model"
)

// Write persists the scan report and legacy diff hashes.
func Write(root string, findingHashPath string, report model.ScanReport) error {
	if err := os.MkdirAll(filepath.Join(root, "log"), 0o755); err != nil {
		return fmt.Errorf("create log dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "db"), 0o755); err != nil {
		return fmt.Errorf("create db dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(findingHashPath), 0o755); err != nil {
		return fmt.Errorf("create finding hash dir: %w", err)
	}

	jsonPath := filepath.Join(root, "db", "report.json")
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	if err := os.WriteFile(jsonPath, data, 0o644); err != nil {
		return fmt.Errorf("write report json: %w", err)
	}

	logText := RenderText(report)
	if err := os.WriteFile(filepath.Join(root, "log", "linux_safescan.log"), []byte(logText), 0o644); err != nil {
		return fmt.Errorf("write text report: %w", err)
	}

	lines := make([]string, 0, len(report.Findings))
	for _, finding := range report.Findings {
		lines = append(lines, finding.Fingerprint())
	}
	sort.Strings(lines)
	if err := os.WriteFile(findingHashPath, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		return fmt.Errorf("write hash db: %w", err)
	}
	return nil
}

// LoadHashes reads the previous finding hash list if present.
func LoadHashes(path string) (map[string]struct{}, error) {
	out := make(map[string]struct{})
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out[line] = struct{}{}
	}
	return out, nil
}

// RenderText creates a human-readable report.
func RenderText(report model.ScanReport) string {
	var b strings.Builder
	findings := report.Findings
	if report.DiffMode {
		findings = report.NewFindings
	}

	b.WriteString("Linux_safescan Security Audit\n")
	b.WriteString(strings.Repeat("=", 32) + "\n")
	b.WriteString(fmt.Sprintf("Version      : %s\n", report.Version))
	b.WriteString(fmt.Sprintf("Author       : %s\n", report.Author))
	b.WriteString(fmt.Sprintf("Repository   : %s\n", report.Repository))
	b.WriteString(fmt.Sprintf("Target       : %s (%s)\n", report.Host.Hostname, report.Host.IP))
	b.WriteString(fmt.Sprintf("Platform     : %s\n", report.Host.OS))
	b.WriteString(fmt.Sprintf("Window       : %s → %s\n", report.StartedAt.Format("2006-01-02 15:04:05"), report.FinishedAt.Format("2006-01-02 15:04:05")))
	if report.DiffMode {
		b.WriteString("Mode         : DIFF ONLY\n")
	} else {
		b.WriteString("Mode         : FULL\n")
	}
	b.WriteString(strings.Repeat("-", 48) + "\n")

	if len(findings) == 0 {
		b.WriteString("No findings.\n")
	} else {
		for i, finding := range findings {
			b.WriteString(fmt.Sprintf("[%03d] %s | %s :: %s\n", i+1, severityLabel(finding.Severity), finding.Category, finding.Name))
			if finding.Time != "" {
				b.WriteString(fmt.Sprintf("Time        : %s\n", finding.Time))
			}
			if finding.User != "" {
				b.WriteString(fmt.Sprintf("User        : %s\n", finding.User))
			}
			if finding.PID != "" {
				b.WriteString(fmt.Sprintf("PID         : %s\n", finding.PID))
			}
			if finding.File != "" {
				b.WriteString(fmt.Sprintf("File        : %s\n", finding.File))
			}
			b.WriteString(fmt.Sprintf("Details     : %s\n", finding.Info))
			if report.Suggestion && finding.Consult != "" {
				b.WriteString(fmt.Sprintf("Reference   : %s\n", finding.Consult))
			}
			if report.Programme && finding.Programme != "" {
				b.WriteString(fmt.Sprintf("Remediation : %s\n", finding.Programme))
			}
			b.WriteString(strings.Repeat("-", 48) + "\n")
		}
	}

	if len(report.OpenServices) > 0 {
		b.WriteString("Open Services:\n")
		for _, line := range report.OpenServices {
			b.WriteString("- " + line + "\n")
		}
	}

	if len(report.Timeline) > 0 {
		b.WriteString("Timeline:\n")
		for _, line := range report.Timeline {
			b.WriteString("- " + line + "\n")
		}
	}

	if len(report.Warnings) > 0 {
		b.WriteString("Warnings:\n")
		for _, warning := range report.Warnings {
			b.WriteString("- " + warning + "\n")
		}
	}

	return b.String()
}

func severityLabel(level model.Severity) string {
	switch level {
	case model.SeverityRisk:
		return "RISK"
	case model.SeveritySuspicious:
		return "SUSPICIOUS"
	default:
		return "INFO"
	}
}
