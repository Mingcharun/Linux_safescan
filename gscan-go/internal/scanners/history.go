package scanners

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/Mingcharun/Linux_safescan/gscan-go/internal/model"
	"github.com/Mingcharun/Linux_safescan/gscan-go/internal/scanner"
)

type historyScanner struct{}

// NewHistoryScanner creates the history scanner.
func NewHistoryScanner() scanner.Runner { return &historyScanner{} }

func (s *historyScanner) Name() string { return "主机历史操作类安全检测" }

func (s *historyScanner) Run(ctx context.Context, rt *scanner.Runtime) ([]model.Finding, error) {
	_ = ctx
	files := []string{"/root/.bash_history"}
	for _, root := range []string{"/home", "/Users"} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			files = append(files, filepath.Join(root, entry.Name(), ".bash_history"))
		}
	}

	findings := make([]model.Finding, 0)
	for _, file := range files {
		fd, err := os.Open(file)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fd)
		for sc.Scan() {
			line := sc.Text()
			if info := rt.AnalyzeText(line); info != "" {
				mtime, user := scanner.FileMeta(file)
				findings = append(findings, model.Finding{
					Category:  s.Name(),
					Name:      "history 文件安全扫描",
					File:      file,
					Time:      mtime,
					User:      user,
					Info:      info,
					Consult:   "[1] cat " + file,
					Severity:  model.SeverityRisk,
					CreatedAt: time.Now(),
				})
			}
		}
		fd.Close()
	}
	return findings, nil
}
