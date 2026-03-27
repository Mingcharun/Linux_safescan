package scanners

import (
	"bufio"
	"context"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Mingcharun/Linux_safescan/internal/model"
	"github.com/Mingcharun/Linux_safescan/internal/scanner"
)

type configScanner struct{}

// NewConfigScanner creates the config scanner.
func NewConfigScanner() scanner.Runner { return &configScanner{} }

func (s *configScanner) Name() string { return "Security Configuration" }

func (s *configScanner) Run(ctx context.Context, rt *scanner.Runtime) ([]model.Finding, error) {
	_ = ctx
	findings := make([]model.Finding, 0)
	findings = append(findings, s.scanDNS(rt)...)
	findings = append(findings, s.scanIPTables()...)
	findings = append(findings, s.scanHosts(rt)...)
	return findings, nil
}

func (s *configScanner) scanDNS(rt *scanner.Runtime) []model.Finding {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	findings := make([]model.Finding, 0)
	for _, ip := range regexp.MustCompile(`([0-9]{1,3}\.){3}[0-9]{1,3}`).FindAllString(string(data), -1) {
		if ip == "8.8.8.8" || !rt.IsForeignIP(ip) {
			continue
		}
		findings = append(findings, model.Finding{
			Category:  s.Name(),
			Name:      "DNS configuration",
			File:      "/etc/resolv.conf",
			Info:      "DNS points to foreign IP: " + ip,
			Consult:   "[1] cat /etc/resolv.conf",
			Severity:  model.SeveritySuspicious,
			Programme: "vi /etc/resolv.conf # update DNS resolver",
			CreatedAt: time.Now(),
		})
	}
	return findings
}

func (s *configScanner) scanIPTables() []model.Finding {
	file := "/etc/sysconfig/iptables"
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
		if strings.Contains(line, "ACCEPT") {
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "Firewall configuration",
				File:      file,
				Info:      "Permissive iptables ACCEPT policy: " + line,
				Consult:   "[1] cat /etc/sysconfig/iptables",
				Severity:  model.SeveritySuspicious,
				Programme: "vi /etc/sysconfig/iptables # tighten ACCEPT rules",
				CreatedAt: time.Now(),
			})
		}
	}
	return findings
}

func (s *configScanner) scanHosts(rt *scanner.Runtime) []model.Finding {
	file := "/etc/hosts"
	fd, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer fd.Close()

	ipPattern := regexp.MustCompile(`(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)`)
	findings := make([]model.Finding, 0)
	sc := bufio.NewScanner(fd)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || !ipPattern.MatchString(fields[0]) {
			continue
		}
		if !rt.IsForeignIP(fields[0]) {
			continue
		}
		findings = append(findings, model.Finding{
			Category:  s.Name(),
			Name:      "/etc/hosts configuration",
			File:      file,
			Info:      "Foreign IP present in hosts: " + fields[0],
			Consult:   "[1] cat /etc/hosts",
			Severity:  model.SeveritySuspicious,
			Programme: "vi /etc/hosts # review entries",
			CreatedAt: time.Now(),
		})
	}
	return findings
}
