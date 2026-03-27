package scanners

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mingcharun/Linux_safescan/internal/model"
	"github.com/Mingcharun/Linux_safescan/internal/scanner"
)

type userScanner struct{}

// NewUserScanner creates the account scanner.
func NewUserScanner() scanner.Runner { return &userScanner{} }

func (s *userScanner) Name() string { return "Account Security" }

func (s *userScanner) Run(ctx context.Context, rt *scanner.Runtime) ([]model.Finding, error) {
	_ = ctx
	findings := make([]model.Finding, 0)
	findings = append(findings, s.scanPasswd()...)
	findings = append(findings, s.scanShadow()...)
	findings = append(findings, s.scanSudoers()...)
	findings = append(findings, s.scanAuthorizedKeys()...)
	findings = append(findings, s.scanPasswordFilePerms()...)
	return findings, nil
}

func (s *userScanner) scanPasswd() []model.Finding {
	fd, err := os.Open("/etc/passwd")
	if err != nil {
		return nil
	}
	defer fd.Close()

	findings := make([]model.Finding, 0)
	sc := bufio.NewScanner(fd)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) < 7 {
			continue
		}
		user := fields[0]
		uid := fields[2]
		gid := fields[3]
		shell := fields[6]
		if uid == "0" && user != "root" {
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "Privileged account check",
				File:      "/etc/passwd",
				User:      user,
				Info:      "Non-root user has uid 0: " + user,
				Consult:   "[1] cat /etc/passwd",
				Severity:  model.SeveritySuspicious,
				Programme: "vi /etc/passwd # drop root privileges",
				CreatedAt: time.Now(),
			})
		}
		if gid == "0" && user != "root" && strings.Contains(shell, "/bin/bash") {
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "Privileged group check",
				File:      "/etc/passwd",
				User:      user,
				Info:      "User in gid 0: " + user,
				Consult:   "[1] cat /etc/passwd",
				Severity:  model.SeveritySuspicious,
				Programme: "vi /etc/passwd # remove from group 0",
				CreatedAt: time.Now(),
			})
		}
	}
	return findings
}

func (s *userScanner) scanShadow() []model.Finding {
	fd, err := os.Open("/etc/shadow")
	if err != nil {
		return nil
	}
	defer fd.Close()

	findings := make([]model.Finding, 0)
	sc := bufio.NewScanner(fd)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) < 2 {
			continue
		}
		if fields[1] == "" {
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "Empty password check",
				File:      "/etc/shadow",
				User:      fields[0],
				Info:      "Account with empty password: " + fields[0],
				Consult:   "[1] cat /etc/shadow",
				Severity:  model.SeverityRisk,
				Programme: "userdel " + fields[0] + " # remove account",
				CreatedAt: time.Now(),
			})
		}
	}
	return findings
}

func (s *userScanner) scanSudoers() []model.Finding {
	fd, err := os.Open("/etc/sudoers")
	if err != nil {
		return nil
	}
	defer fd.Close()

	findings := make([]model.Finding, 0)
	sc := bufio.NewScanner(fd)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "%") {
			continue
		}
		if strings.Contains(line, "ALL=(ALL)") {
			user := strings.Fields(line)[0]
			if user == "root" {
				continue
			}
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "sudoers privilege check",
				File:      "/etc/sudoers",
				User:      user,
				Info:      fmt.Sprintf("User %s can elevate via sudo", user),
				Consult:   "[1] cat /etc/sudoers",
				Severity:  model.SeverityRisk,
				Programme: "vi /etc/sudoers # adjust sudo policy",
				CreatedAt: time.Now(),
			})
		}
	}
	return findings
}

func (s *userScanner) scanAuthorizedKeys() []model.Finding {
	findings := make([]model.Finding, 0)
	files := []string{"/root/.ssh/authorized_keys"}
	for _, root := range []string{"/home"} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			files = append(files, filepath.Join(root, entry.Name(), ".ssh", "authorized_keys"))
		}
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil || len(data) == 0 {
			continue
		}
		keys := make([]string, 0)
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) >= 3 {
				keys = append(keys, fields[2])
			}
		}
		findings = append(findings, model.Finding{
			Category:  s.Name(),
			Name:      "Authorized keys audit",
			File:      file,
			Info:      "Passwordless login enabled; client names: " + strings.Join(keys, " & "),
			Consult:   "[1] cat " + file,
			Severity:  model.SeveritySuspicious,
			Programme: "vi " + file + " # remove keys",
			CreatedAt: time.Now(),
		})
	}
	return findings
}

func (s *userScanner) scanPasswordFilePerms() []model.Finding {
	findings := make([]model.Finding, 0)
	for _, path := range []string{"/etc/passwd", "/etc/shadow"} {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		mode := info.Mode().String()
		if path == "/etc/passwd" && mode != "-rw-r--r--" {
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "Credential file permissions",
				File:      path,
				Info:      "passwd permissions not -rw-r--r--",
				Consult:   "ls -l /etc/passwd",
				Severity:  model.SeveritySuspicious,
				CreatedAt: time.Now(),
			})
		}
		if path == "/etc/shadow" && mode != "----------" {
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "Credential file permissions",
				File:      path,
				Info:      "shadow permissions not ----------",
				Consult:   "ls -l /etc/shadow",
				Severity:  model.SeveritySuspicious,
				CreatedAt: time.Now(),
			})
		}
	}
	return findings
}
