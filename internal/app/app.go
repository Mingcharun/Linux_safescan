package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Mingcharun/Linux_safescan/internal/config"
	"github.com/Mingcharun/Linux_safescan/internal/geoip"
	"github.com/Mingcharun/Linux_safescan/internal/model"
	"github.com/Mingcharun/Linux_safescan/internal/report"
	"github.com/Mingcharun/Linux_safescan/internal/rules"
	"github.com/Mingcharun/Linux_safescan/internal/scanner"
	"github.com/Mingcharun/Linux_safescan/internal/scanners"
)

// Run executes the scanner application.
func Run(ctx context.Context, opts config.Options) error {
	if opts.Version {
		fmt.Println(config.Version)
		return nil
	}

	if opts.LogBackup {
		return backupLogs(opts.OutputRoot)
	}

	if opts.InstallJob {
		scheduledHour = opts.JobHour
		return installCrontab(ctx, opts)
	}

	if opts.SearchOnly {
		return scanners.RunSearchMode(ctx, opts)
	}

	if err := os.MkdirAll(filepath.Join(opts.OutputRoot, "db"), 0o755); err != nil {
		return fmt.Errorf("create output db dir: %w", err)
	}

	host := model.HostInfo{
		Hostname: hostname(),
		IP:       scanner.ProbeOutboundIP(),
		OS:       hostOS(),
		Time:     time.Now(),
	}

	corpus, err := rules.Load(opts.RulesDir)
	if err != nil {
		return err
	}
	geo, err := geoip.Open(opts.GeoIPDB)
	if err != nil {
		return err
	}

	rt := &scanner.Runtime{
		Options: opts,
		Rules:   corpus,
		GeoIP:   geo,
		Host:    host,
	}

	startedAt := time.Now()
	runners := []scanner.Runner{
		scanners.NewSysInitScanner(),
		scanners.NewHistoryScanner(),
		scanners.NewFileScanner(),
		scanners.NewProcessScanner(),
		scanners.NewNetworkScanner(),
		scanners.NewBackdoorScanner(),
		scanners.NewUserScanner(),
		scanners.NewConfigScanner(),
	}
	if !opts.DisableLogScan {
		runners = append(runners, scanners.NewLogScanner())
	}
	if !opts.DisableRootkit {
		runners = append(runners, scanners.NewRootkitScanner())
	}
	if !opts.DisableWebshell {
		runners = append(runners, scanners.NewWebshellScanner())
	}

	allFindings := make([]model.Finding, 0, 128)
	for _, runner := range runners {
		findings, err := runner.Run(ctx, rt)
		if err != nil {
			rt.Warn("%s 扫描失败: %v", runner.Name(), err)
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	sort.SliceStable(allFindings, func(i, j int) bool {
		return allFindings[i].Time < allFindings[j].Time
	})

	reportData := model.ScanReport{
		Version:    config.Version,
		Author:     config.Author,
		Repository: config.RepositoryURL,
		StartedAt:  startedAt,
		FinishedAt: time.Now(),
		Host:       host,
		Findings:   dedupeFindings(allFindings),
		Warnings:   append([]string{}, rt.Warnings...),
		DiffMode:   opts.Diff,
		Suggestion: opts.Suggestion,
		Programme:  opts.Programme,
	}

	if opts.Diff {
		oldHashes, err := report.LoadHashes(opts.FindingHashDB)
		if err != nil {
			return fmt.Errorf("load previous hashes: %w", err)
		}
		for _, finding := range reportData.Findings {
			if _, ok := oldHashes[finding.Fingerprint()]; !ok {
				reportData.NewFindings = append(reportData.NewFindings, finding)
			}
		}
	}

	reportData.OpenServices = scanners.DiscoverOpenServices(ctx)
	reportData.Timeline = buildTimeline(displayFindings(reportData, opts.Diff))

	if err := report.Write(opts.OutputRoot, opts.FindingHashDB, reportData); err != nil {
		return err
	}

	fmt.Printf("主机信息: %s / %s / %s\n", reportData.Host.Hostname, reportData.Host.IP, reportData.Host.OS)
	fmt.Printf("扫描完成，共发现 %d 条异常，结果保存在 %s\n", len(displayFindings(reportData, opts.Diff)), opts.OutputRoot)
	return nil
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return name
}

func hostOS() string {
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
			}
		}
	}
	return runtime.GOOS
}

func dedupeFindings(in []model.Finding) []model.Finding {
	seen := make(map[string]struct{}, len(in))
	out := make([]model.Finding, 0, len(in))
	for _, finding := range in {
		key := finding.Fingerprint()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, finding)
	}
	return out
}

func buildTimeline(findings []model.Finding) []string {
	lines := make([]string, 0, len(findings))
	for i, finding := range findings {
		when := finding.Time
		if when == "" {
			when = "未知时间"
		}
		lines = append(lines, fmt.Sprintf("[%d][%s][%s] %s / %s", i+1, when, severityText(finding.Severity), finding.Category, finding.Info))
	}
	return lines
}

func displayFindings(reportData model.ScanReport, diff bool) []model.Finding {
	if diff {
		return reportData.NewFindings
	}
	return reportData.Findings
}

func severityText(level model.Severity) string {
	switch level {
	case model.SeverityRisk:
		return "风险"
	case model.SeveritySuspicious:
		return "可疑"
	default:
		return "信息"
	}
}
