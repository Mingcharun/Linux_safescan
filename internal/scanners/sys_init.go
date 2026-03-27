package scanners

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mingcharun/Linux_safescan/internal/model"
	"github.com/Mingcharun/Linux_safescan/internal/scanner"
)

type sysInitScanner struct{}

// NewSysInitScanner creates the alias scanner.
func NewSysInitScanner() scanner.Runner { return &sysInitScanner{} }

func (s *sysInitScanner) Name() string { return "Shell Alias Checks" }

func (s *sysInitScanner) Run(ctx context.Context, rt *scanner.Runtime) ([]model.Finding, error) {
	_ = ctx
	critical := []string{"ps", "strings", "netstat", "find", "echo", "iptables", "lastlog", "who", "ifconfig", "ssh"}
	files := []string{"/root/.bashrc", "/root/.bash_profile", "/etc/bashrc", "/etc/profile"}
	findings := make([]model.Finding, 0)

	for _, homeRoot := range []string{"/home"} {
		entries, err := os.ReadDir(homeRoot)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			files = append(files, filepath.Join(homeRoot, entry.Name(), ".bashrc"))
			files = append(files, filepath.Join(homeRoot, entry.Name(), ".bash_profile"))
		}
	}

	for _, file := range files {
		fd, err := os.Open(file)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fd)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if !strings.HasPrefix(line, "alias ") {
				continue
			}
			for _, cmd := range critical {
				if strings.Contains(line, "alias "+cmd+"=") {
					mtime, user := scanner.FileMeta(file)
					findings = append(findings, model.Finding{
						Category:  s.Name(),
						Name:      "Initialization alias check",
						File:      file,
						Time:      mtime,
						User:      user,
						Info:      "Suspicious alias detected: " + line,
						Consult:   "[1] alias [2] cat " + file,
						Severity:  model.SeveritySuspicious,
						Programme: "vi " + file + " # remove malicious alias",
						CreatedAt: time.Now(),
					})
				}
			}
		}
		fd.Close()
	}

	return findings, nil
}
