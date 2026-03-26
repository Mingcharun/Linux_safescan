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

func (s *processScanner) Name() string { return "进程类安全检测" }

func (s *processScanner) Run(ctx context.Context, rt *scanner.Runtime) ([]model.Finding, error) {
	findings := make([]model.Finding, 0)
	processes, err := scanner.ListProcesses(ctx)
	if err != nil {
		return nil, err
	}

	for _, proc := range processes {
		if proc.CPU > 70 {
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "CPU 过载扫描",
				PID:       proc.PID,
				User:      proc.User,
				Info:      "进程使用 CPU 过大: " + proc.Cmd,
				Consult:   "[1] ps -efwww",
				Severity:  model.SeveritySuspicious,
				Programme: "kill " + proc.PID + " # 关闭恶意进程",
				CreatedAt: time.Now(),
			})
		}
		if proc.MEM > 70 {
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "内存过载扫描",
				PID:       proc.PID,
				User:      proc.User,
				Info:      "进程使用内存过大: " + proc.Cmd,
				Consult:   "[1] ps -efwww",
				Severity:  model.SeveritySuspicious,
				Programme: "kill " + proc.PID + " # 关闭恶意进程",
				CreatedAt: time.Now(),
			})
		}
		if scanner.CheckShell(proc.Cmd) {
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "反弹 shell 类进程安全扫描",
				PID:       proc.PID,
				User:      proc.User,
				Info:      "对应进程信息: " + proc.Cmd,
				Consult:   "[1] ps -efwww",
				Severity:  model.SeverityRisk,
				Programme: "kill " + proc.PID + " # 关闭恶意进程",
				CreatedAt: time.Now(),
			})
		}
		if looksSuspiciousProcess(proc.Cmd) {
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "可疑进程信息扫描",
				PID:       proc.PID,
				User:      proc.User,
				Info:      proc.Cmd,
				Consult:   "[1] ps -efwww",
				Severity:  model.SeveritySuspicious,
				Programme: "kill " + proc.PID + " # 关闭恶意进程",
				CreatedAt: time.Now(),
			})
		}

		exePath := filepath.Join("/proc", proc.PID, "exe")
		target, err := os.Readlink(exePath)
		if err == nil {
			if desc := rt.AnalyzeFile(target); desc != "" {
				findings = append(findings, model.Finding{
					Category:  s.Name(),
					Name:      "exe 程序进程安全扫描",
					File:      target,
					PID:       proc.PID,
					User:      proc.User,
					Info:      desc,
					Consult:   "[1] ls -a " + exePath + " [2] strings " + exePath,
					Severity:  model.SeverityRisk,
					Programme: "kill " + proc.PID + " # 关闭恶意进程",
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
			Name:      "隐藏进程扫描",
			PID:       pid,
			Info:      fmt.Sprintf("进程 ID %s 隐藏了进程信息，未出现在进程列表中", pid),
			Consult:   "[1] cat /proc/$$/mountinfo [2] umount /proc/" + pid + " [3] ps -ef | grep " + pid,
			Severity:  model.SeverityRisk,
			Programme: "umount /proc/" + pid + " && kill " + pid + " # 关闭隐藏进程并结束进程",
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
