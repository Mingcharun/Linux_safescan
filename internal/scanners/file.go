package scanners

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mingcharun/Linux_safescan/internal/model"
	"github.com/Mingcharun/Linux_safescan/internal/scanner"
)

type fileScanner struct{}

// NewFileScanner creates the file scanner.
func NewFileScanner() scanner.Runner { return &fileScanner{} }

func (s *fileScanner) Name() string { return "Filesystem Integrity" }

func (s *fileScanner) Run(ctx context.Context, rt *scanner.Runtime) ([]model.Finding, error) {
	findings := make([]model.Finding, 0)

	baseline, err := loadHashBaseline(rt.Options.SystemHashDB)
	if err != nil {
		rt.Warn("failed to read baseline: %v", err)
	}
	current := s.currentHashes()
	if len(baseline) == 0 {
		if err := writeHashBaseline(rt.Options.SystemHashDB, current); err != nil {
			rt.Warn("failed to initialize baseline: %v", err)
		}
	} else {
		for path, hash := range current {
			old, ok := baseline[path]
			if ok && old == hash {
				continue
			}
			action := "CREATE"
			if ok {
				action = "MODIFY"
			}
			info := fmt.Sprintf("Detected %s of protected binary %s (hash: %s)", action, path, hash)
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "Protected binary hash diff",
				File:      path,
				Info:      info,
				Consult:   "[1] strings " + path + " [2] cat " + path,
				Severity:  model.SeverityRisk,
				Programme: "rm " + path + " # remove malicious file",
				CreatedAt: time.Now(),
			})
		}
		if err := writeHashBaseline(rt.Options.SystemHashDB, current); err != nil {
			rt.Warn("failed to update baseline: %v", err)
		}
	}

	findings = append(findings, s.scanImportantBinaries(rt)...)
	findings = append(findings, s.scanRoots(rt, "Temp directory sweep", []string{"/tmp", "/var/tmp", "/dev/shm"})...)
	findings = append(findings, s.scanRoots(rt, "Home directory sweep", []string{"/home", "/root"})...)
	findings = append(findings, s.scanHidden(ctx)...)

	return findings, nil
}

func (s *fileScanner) scanImportantBinaries(rt *scanner.Runtime) []model.Finding {
	roots := []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"}
	allow := importantBinaryNames()
	findings := make([]model.Finding, 0)
	for _, root := range roots {
		_ = scanner.WalkFiles(root, func(path string, info os.FileInfo) error {
			if !allow[filepath.Base(path)] {
				return nil
			}
			if desc := rt.AnalyzeFile(path); desc != "" {
				findings = append(findings, model.Finding{
					Category:  s.Name(),
					Name:      "System binary analysis",
					File:      path,
					Info:      desc,
					Consult:   "[1] rpm -qa " + path + " [2] strings " + path,
					Severity:  model.SeverityRisk,
					Programme: "rm " + path + " # remove malicious file",
					CreatedAt: time.Now(),
				})
			}
			return nil
		})
	}
	return findings
}

func (s *fileScanner) scanRoots(rt *scanner.Runtime, name string, roots []string) []model.Finding {
	findings := make([]model.Finding, 0)
	for _, root := range roots {
		_ = scanner.WalkFiles(root, func(path string, info os.FileInfo) error {
			if desc := rt.AnalyzeFile(path); desc != "" {
				findings = append(findings, model.Finding{
					Category:  s.Name(),
					Name:      name,
					File:      path,
					Info:      desc,
					Consult:   "[1] rpm -qa " + path + " [2] strings " + path,
					Severity:  model.SeverityRisk,
					Programme: "rm " + path + " # remove malicious file",
					CreatedAt: time.Now(),
				})
			}
			return nil
		})
	}
	return findings
}

func (s *fileScanner) scanHidden(ctx context.Context) []model.Finding {
	lines, err := scanner.RunLines(ctx, "find", "/", "!", "-path", "/proc/*", "!", "-path", "/sys/*", "!", "-path", "/run/*", "!", "-path", "/private/*", "-name", "..*")
	if err != nil {
		return nil
	}
	findings := make([]model.Finding, 0, len(lines))
	for _, file := range lines {
		if strings.TrimSpace(file) == "" || file == "/usr/share/man/man1/..1.gz" {
			continue
		}
		findings = append(findings, model.Finding{
			Category:  s.Name(),
			Name:      "Hidden file sweep",
			File:      file,
			Info:      "Suspicious hidden file: " + file,
			Consult:   "[1] ls -l " + file + " [2] strings " + file,
			Severity:  model.SeveritySuspicious,
			Programme: "rm " + file + " # remove malicious file",
			CreatedAt: time.Now(),
		})
	}
	return findings
}

func (s *fileScanner) currentHashes() map[string]string {
	current := make(map[string]string)
	allow := importantBinaryNames()
	for _, root := range []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"} {
		_ = scanner.WalkFiles(root, func(path string, info os.FileInfo) error {
			if !allow[filepath.Base(path)] {
				return nil
			}
			if sum, err := fileMD5(path); err == nil {
				current[path] = sum
			}
			return nil
		})
	}
	return current
}

func importantBinaryNames() map[string]bool {
	names := []string{
		"depmod", "fsck", "fuser", "ifconfig", "ifdown", "ifup", "init", "insmod", "ip", "lsmod", "modinfo",
		"modprobe", "nologin", "rmmod", "route", "rsyslogd", "runlevel", "sulogin", "sysctl", "awk", "basename",
		"bash", "cat", "chmod", "chown", "cp", "cut", "date", "df", "dmesg", "echo", "egrep", "env", "fgrep",
		"find", "grep", "kill", "logger", "login", "ls", "mail", "mktemp", "more", "mount", "mv", "netstat", "ping",
		"ps", "pwd", "readlink", "rpm", "sed", "sh", "sort", "su", "touch", "uname", "gawk", "mailx", "adduser",
		"chroot", "groupadd", "groupdel", "groupmod", "grpck", "lsof", "pwck", "sestatus", "sshd", "useradd",
		"userdel", "usermod", "vipw", "chattr", "curl", "diff", "dirname", "du", "file", "groups", "head", "id",
		"ipcs", "killall", "last", "lastlog", "ldd", "less", "lsattr", "md5sum", "newgrp", "passwd", "perl", "pgrep",
		"pkill", "pstree", "runcon", "sha1sum", "sha224sum", "sha256sum", "sha384sum", "sha512sum", "size", "ssh",
		"stat", "strace", "strings", "sudo", "tail", "test", "top", "tr", "uniq", "users", "vmstat", "w", "watch",
		"wc", "wget", "whereis", "which", "who", "whoami",
	}
	out := make(map[string]bool, len(names))
	for _, name := range names {
		out[name] = true
	}
	return out
}

func fileMD5(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:]), nil
}

func loadHashBaseline(path string) (map[string]string, error) {
	result := make(map[string]string)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return result, nil
		}
		return nil, err
	}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := sc.Text()
		parts := strings.Split(line, "||")
		if len(parts) < 2 {
			continue
		}
		result[parts[0]] = parts[1]
	}
	return result, sc.Err()
}

func writeHashBaseline(path string, values map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var b strings.Builder
	for file, hash := range values {
		b.WriteString(file + "||" + hash + "||" + fmt.Sprintf("%d", time.Now().Unix()) + "\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
