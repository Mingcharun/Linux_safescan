package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/grayddq/gscan-go/internal/model"
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

	jsonPath := filepath.Join(root, "db", "findings.json")
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	if err := os.WriteFile(jsonPath, data, 0o644); err != nil {
		return fmt.Errorf("write report json: %w", err)
	}

	logText := RenderText(report)
	if err := os.WriteFile(filepath.Join(root, "log", "gscan.log"), []byte(logText), 0o644); err != nil {
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
	if len(report.NewFindings) > 0 {
		findings = report.NewFindings
	}

	b.WriteString("GScan Go Report\n")
	b.WriteString(fmt.Sprintf("Version: %s\n", report.Version))
	b.WriteString(fmt.Sprintf("Host: %s (%s)\n", report.Host.Hostname, report.Host.IP))
	b.WriteString(fmt.Sprintf("OS: %s\n", report.Host.OS))
	b.WriteString(fmt.Sprintf("Started: %s\n", report.StartedAt.Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("Finished: %s\n", report.FinishedAt.Format("2006-01-02 15:04:05")))
	b.WriteString(strings.Repeat("-", 40) + "\n")

	if len(findings) == 0 {
		b.WriteString("本次扫描未发现明确异常。\n")
	} else {
		for i, finding := range findings {
			b.WriteString(fmt.Sprintf("[%d][%s] %s / %s\n", i+1, severityLabel(finding.Severity), finding.Category, finding.Name))
			if finding.Time != "" {
				b.WriteString(fmt.Sprintf("时间: %s\n", finding.Time))
			}
			if finding.User != "" {
				b.WriteString(fmt.Sprintf("用户: %s\n", finding.User))
			}
			if finding.PID != "" {
				b.WriteString(fmt.Sprintf("PID: %s\n", finding.PID))
			}
			if finding.File != "" {
				b.WriteString(fmt.Sprintf("文件: %s\n", finding.File))
			}
			b.WriteString(fmt.Sprintf("详情: %s\n", finding.Info))
			if finding.Consult != "" {
				b.WriteString(fmt.Sprintf("排查参考: %s\n", finding.Consult))
			}
			if finding.Programme != "" {
				b.WriteString(fmt.Sprintf("处理建议: %s\n", finding.Programme))
			}
			b.WriteString(strings.Repeat("-", 40) + "\n")
		}
	}

	if len(report.Timeline) > 0 {
		b.WriteString("时间线摘要:\n")
		for _, line := range report.Timeline {
			b.WriteString("- " + line + "\n")
		}
	}

	if len(report.Warnings) > 0 {
		b.WriteString("警告:\n")
		for _, warning := range report.Warnings {
			b.WriteString("- " + warning + "\n")
		}
	}

	return b.String()
}

func severityLabel(level model.Severity) string {
	switch level {
	case model.SeverityRisk:
		return "风险"
	case model.SeveritySuspicious:
		return "可疑"
	default:
		return "信息"
	}
}
