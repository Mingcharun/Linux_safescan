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

type backdoorScanner struct{}

// NewBackdoorScanner creates the backdoor scanner.
func NewBackdoorScanner() scanner.Runner { return &backdoorScanner{} }

func (s *backdoorScanner) Name() string { return "Backdoor Checks" }

func (s *backdoorScanner) Run(ctx context.Context, rt *scanner.Runtime) ([]model.Finding, error) {
	findings := make([]model.Finding, 0)
	findings = append(findings, s.scanShellConfigs(rt, "LD_PRELOAD backdoor", "LD_PRELOAD", true)...)
	findings = append(findings, s.scanShellConfigs(rt, "LD_AOUT_PRELOAD backdoor", "LD_AOUT_PRELOAD", true)...)
	findings = append(findings, s.scanShellConfigs(rt, "LD_ELF_PRELOAD backdoor", "LD_ELF_PRELOAD", true)...)
	findings = append(findings, s.scanShellConfigs(rt, "LD_LIBRARY_PATH backdoor", "LD_LIBRARY_PATH", true)...)
	findings = append(findings, s.scanShellConfigs(rt, "PROMPT_COMMAND backdoor", "PROMPT_COMMAND", true)...)
	findings = append(findings, s.scanShellConfigs(rt, "Unknown env backdoor", "PATH", false)...)
	findings = append(findings, s.scanLDSoPreload(rt)...)
	findings = append(findings, s.scanCron(rt)...)
	findings = append(findings, s.scanSSHBackdoor(ctx)...)
	findings = append(findings, s.scanSSHWrapper()...)
	findings = append(findings, s.scanTextConfig(rt, "/etc/inetd.conf", "inetd.conf backdoor")...)
	findings = append(findings, s.scanXinetd(rt)...)
	findings = append(findings, s.scanSetUID(ctx)...)
	findings = append(findings, s.scanStartupItems(rt)...)
	return findings, nil
}

func (s *backdoorScanner) scanShellConfigs(rt *scanner.Runtime, name, tag string, exportOnly bool) []model.Finding {
	files := []string{
		"/root/.bashrc", "/root/.tcshrc", "/root/.bash_profile", "/root/.cshrc",
		"/etc/bashrc", "/etc/profile", "/etc/csh.login", "/etc/csh.cshrc",
	}
	for _, root := range []string{"/home"} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			home := filepath.Join(root, entry.Name())
			files = append(files,
				filepath.Join(home, ".bashrc"),
				filepath.Join(home, ".bash_profile"),
				filepath.Join(home, ".tcshrc"),
				filepath.Join(home, ".cshrc"),
			)
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
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if exportOnly {
				if !strings.Contains(trimmed, "export "+tag) {
					continue
				}
				findings = append(findings, model.Finding{
					Category:  s.Name(),
					Name:      name,
					File:      file,
					Info:      trimmed,
					Consult:   "[1] echo $" + tag + " [2] cat " + file,
					Severity:  model.SeveritySuspicious,
					Programme: "vi " + file + " # remove " + tag + " setting",
					CreatedAt: time.Now(),
				})
				continue
			}
			if desc := rt.AnalyzeFile(file); desc != "" {
				findings = append(findings, model.Finding{
					Category:  s.Name(),
					Name:      name,
					File:      file,
					Info:      desc,
					Consult:   "[1] echo $" + tag + " [2] cat " + file,
					Severity:  model.SeveritySuspicious,
					CreatedAt: time.Now(),
				})
				break
			}
		}
		fd.Close()
	}
	return findings
}

func (s *backdoorScanner) scanLDSoPreload(rt *scanner.Runtime) []model.Finding {
	file := "/etc/ld.so.preload"
	fd, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer fd.Close()

	findings := make([]model.Finding, 0)
	sc := bufio.NewScanner(fd)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if desc := rt.AnalyzeText(line); desc != "" || line != "" {
			if desc == "" {
				desc = line
			}
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "ld.so.preload backdoor",
				File:      file,
				Info:      desc,
				Consult:   "[1] cat /etc/ld.so.preload",
				Severity:  model.SeverityRisk,
				Programme: "vi /etc/ld.so.preload # remove all shared object entries",
				CreatedAt: time.Now(),
			})
		}
	}
	return findings
}

func (s *backdoorScanner) scanCron(rt *scanner.Runtime) []model.Finding {
	findings := make([]model.Finding, 0)
	for _, root := range []string{"/var/spool/cron", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.hourly", "/etc/cron.monthly"} {
		_ = scanner.WalkFiles(root, func(path string, info os.FileInfo) error {
			fd, err := os.Open(path)
			if err != nil {
				return nil
			}
			defer fd.Close()
			sc := bufio.NewScanner(fd)
			for sc.Scan() {
				line := sc.Text()
				if desc := rt.AnalyzeText(line); desc != "" {
					findings = append(findings, model.Finding{
						Category:  s.Name(),
						Name:      "cron backdoor",
						File:      path,
						Info:      desc,
						Consult:   "[1] cat " + path,
						Severity:  model.SeverityRisk,
						Programme: "vi " + path + " # remove malicious cron entry",
						CreatedAt: time.Now(),
					})
				}
			}
			return nil
		})
	}
	return findings
}

func (s *backdoorScanner) scanSSHBackdoor(ctx context.Context) []model.Finding {
	findings := make([]model.Finding, 0)
	for _, service := range DiscoverOpenServices(ctx) {
		if !strings.Contains(service, "sshd") || strings.Contains(service, ":22 ") || strings.HasSuffix(service, ":22") {
			continue
		}
		findings = append(findings, model.Finding{
			Category:  s.Name(),
			Name:      "SSH backdoor",
			Info:      "Found sshd listening on a non-22 port: " + service,
			Consult:   "[1] ss -lntp",
			Severity:  model.SeverityRisk,
			CreatedAt: time.Now(),
		})
	}
	return findings
}

func (s *backdoorScanner) scanSSHWrapper() []model.Finding {
	file := "/usr/sbin/sshd"
	info, err := os.Stat(file)
	if err != nil {
		return nil
	}
	if info.Mode().Perm()&0o111 != 0 && scanner.IsELF(file) {
		return nil
	}
	return []model.Finding{{
		Category:  s.Name(),
		Name:      "SSH wrapper backdoor",
		File:      file,
		Info:      "/usr/sbin/sshd is not a valid ELF executable (possible wrapper/tampering)",
		Consult:   "[1] file /usr/sbin/sshd [2] cat /usr/sbin/sshd",
		Severity:  model.SeverityRisk,
		Programme: "reinstall openssh-server and restore sshd",
		CreatedAt: time.Now(),
	}}
}

func (s *backdoorScanner) scanTextConfig(rt *scanner.Runtime, file string, name string) []model.Finding {
	fd, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer fd.Close()
	findings := make([]model.Finding, 0)
	sc := bufio.NewScanner(fd)
	for sc.Scan() {
		if desc := rt.AnalyzeText(sc.Text()); desc != "" {
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      name,
				File:      file,
				Info:      desc,
				Consult:   "[1] cat " + file,
				Severity:  model.SeverityRisk,
				Programme: "vi " + file + " # remove suspicious entries",
				CreatedAt: time.Now(),
			})
		}
	}
	return findings
}

func (s *backdoorScanner) scanXinetd(rt *scanner.Runtime) []model.Finding {
	findings := make([]model.Finding, 0)
	_ = scanner.WalkFiles("/etc/xinetd.d", func(path string, info os.FileInfo) error {
		findings = append(findings, s.scanTextConfig(rt, path, "xinetd.conf backdoor")...)
		return nil
	})
	return findings
}

func (s *backdoorScanner) scanSetUID(ctx context.Context) []model.Finding {
	lines, err := scanner.RunLines(ctx, "find", "/", "!", "-path", "/proc/*", "-type", "f", "-perm", "-4000")
	if err != nil {
		return nil
	}
	allow := []string{"pam_timestamp_check", "unix_chkpwd", "ping", "mount", "su", "pt_chown", "ssh-keysign", "at", "passwd", "chsh", "crontab", "chfn", "usernetctl", "staprun", "newgrp", "chage", "dhcp", "helper", "pkexec", "top", "Xorg", "nvidia-modprobe", "quota", "login", "security_authtrampoline", "authopen", "traceroute6", "traceroute", "ps"}
	findings := make([]model.Finding, 0)
	for _, file := range lines {
		safe := false
		for _, item := range allow {
			if strings.Contains(file, item) {
				safe = true
				break
			}
		}
		if safe {
			continue
		}
		findings = append(findings, model.Finding{
			Category:  s.Name(),
			Name:      "setuid backdoor",
			File:      file,
			Info:      "Binary has setuid bit set; may allow privilege escalation: " + file,
			Consult:   "[1] ls -l " + file,
			Severity:  model.SeverityRisk,
			Programme: "chmod u-s " + file + " # remove setuid",
			CreatedAt: time.Now(),
		})
	}
	return findings
}

func (s *backdoorScanner) scanStartupItems(rt *scanner.Runtime) []model.Finding {
	findings := make([]model.Finding, 0)
	for _, path := range []string{"/etc/init.d", "/etc/rc.d", "/etc/rc.local", "/usr/local/etc/rc.d", "/usr/local/etc/rc.local", "/etc/conf.d/local.start", "/etc/inittab", "/etc/systemd/system"} {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			if desc := rt.AnalyzeFile(path); desc != "" {
				findings = append(findings, model.Finding{
					Category:  s.Name(),
					Name:      "Startup entry backdoor",
					File:      path,
					Info:      desc,
					Consult:   "[1] cat " + path,
					Severity:  model.SeverityRisk,
					Programme: "vi " + path + " # remove suspicious entries",
					CreatedAt: time.Now(),
				})
			}
			continue
		}
		_ = scanner.WalkFiles(path, func(file string, _ os.FileInfo) error {
			if desc := rt.AnalyzeFile(file); desc != "" {
				findings = append(findings, model.Finding{
					Category:  s.Name(),
					Name:      "Startup entry backdoor",
					File:      file,
					Info:      desc,
					Consult:   "[1] cat " + file,
					Severity:  model.SeverityRisk,
					Programme: "vi " + file + " # remove suspicious entries",
					CreatedAt: time.Now(),
				})
			}
			return nil
		})
	}
	return findings
}
