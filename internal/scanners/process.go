package scanners

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mingcharun/Linux_safescan/internal/model"
	"github.com/Mingcharun/Linux_safescan/internal/scanner"
)

type processScanner struct{}

// NewProcessScanner creates the process scanner.
func NewProcessScanner() scanner.Runner { return &processScanner{} }

func (s *processScanner) Name() string { return "Process Anomalies" }

func (s *processScanner) Run(ctx context.Context, rt *scanner.Runtime) ([]model.Finding, error) {
	findings := make([]model.Finding, 0)
	processes, err := scanner.ListProcesses(ctx)
	if err != nil {
		return nil, err
	}

	for _, proc := range processes {
		if proc.CPU > float64(rt.Options.CPUThreshold) {
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "High CPU usage",
				PID:       proc.PID,
				User:      proc.User,
				Info:      "Process using excessive CPU: " + proc.Cmd,
				Consult:   "[1] ps -efwww",
				Severity:  model.SeveritySuspicious,
				Programme: "kill " + proc.PID + " # terminate process",
				CreatedAt: time.Now(),
			})
		}
		if proc.MEM > float64(rt.Options.MEMThreshold) {
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "High memory usage",
				PID:       proc.PID,
				User:      proc.User,
				Info:      "Process using excessive memory: " + proc.Cmd,
				Consult:   "[1] ps -efwww",
				Severity:  model.SeveritySuspicious,
				Programme: "kill " + proc.PID + " # terminate process",
				CreatedAt: time.Now(),
			})
		}
		if scanner.CheckShell(proc.Cmd) {
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "Reverse shell-like process",
				PID:       proc.PID,
				User:      proc.User,
				Info:      "Suspicious process: " + proc.Cmd,
				Consult:   "[1] ps -efwww",
				Severity:  model.SeverityRisk,
				Programme: "kill " + proc.PID + " # terminate process",
				CreatedAt: time.Now(),
			})
		}
		if looksSuspiciousProcess(proc.Cmd) {
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "Suspicious process commandline",
				PID:       proc.PID,
				User:      proc.User,
				Info:      proc.Cmd,
				Consult:   "[1] ps -efwww",
				Severity:  model.SeveritySuspicious,
				Programme: "kill " + proc.PID + " # terminate process",
				CreatedAt: time.Now(),
			})
		}

		exePath := filepath.Join("/proc", proc.PID, "exe")
		target, err := os.Readlink(exePath)
		if err == nil {
			if desc := rt.AnalyzeFile(target); desc != "" {
				findings = append(findings, model.Finding{
					Category:  s.Name(),
					Name:      "Executable image analysis",
					File:      target,
					PID:       proc.PID,
					User:      proc.User,
					Info:      desc,
					Consult:   "[1] ls -a " + exePath + " [2] strings " + exePath,
					Severity:  model.SeverityRisk,
					Programme: "kill " + proc.PID + " # terminate process",
					CreatedAt: time.Now(),
				})
			}
		}
	}

	findings = append(findings, s.scanHiddenProcesses(ctx)...)
	return findings, nil
}

func (s *processScanner) scanHiddenProcesses(ctx context.Context) []model.Finding {
	lines, err := scanner.RunLines(ctx, "ps", "-e", "-o", "pid=")
	if err != nil {
		return nil
	}
	psPIDs := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		psPIDs[strings.TrimSpace(line)] = struct{}{}
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	findings := make([]model.Finding, 0)
	for _, entry := range entries {
		pid := entry.Name()
		if _, ok := psPIDs[pid]; ok || !isDigits(pid) {
			continue
		}
		findings = append(findings, model.Finding{
			Category:  s.Name(),
			Name:      "Hidden process detection",
			PID:       pid,
			Info:      fmt.Sprintf("Process %s not visible in ps output (possible hidden process)", pid),
			Consult:   "[1] cat /proc/$$/mountinfo [2] umount /proc/" + pid + " [3] ps -ef | grep " + pid,
			Severity:  model.SeverityRisk,
			Programme: "umount /proc/" + pid + " && kill " + pid + " # unmount and terminate",
			CreatedAt: time.Now(),
		})
	}
	return findings
}

func looksSuspiciousProcess(cmd string) bool {
	for _, token := range []string{"minerd", "r00t", "sqlmap", "nmap", "hydra", "aircrack"} {
		if strings.Contains(strings.ToLower(cmd), token) {
			return true
		}
	}
	return false
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}
