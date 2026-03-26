package scanners

import (
	"bufio"
	"context"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/grayddq/gscan-go/internal/model"
	"github.com/grayddq/gscan-go/internal/scanner"
)

type configScanner struct{}

// NewConfigScanner creates the config scanner.
func NewConfigScanner() scanner.Runner { return &configScanner{} }

func (s *configScanner) Name() string { return "配置类安全检测" }

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
			Name:      "DNS 安全配置",
			File:      "/etc/resolv.conf",
			Info:      "DNS 设置为境外 IP: " + ip,
			Consult:   "[1] cat /etc/resolv.conf",
			Severity:  model.SeveritySuspicious,
			Programme: "vi /etc/resolv.conf # 删除或更改境外 DNS 配置",
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
				Name:      "防火墙安全配置",
				File:      file,
				Info:      "存在 iptables ACCEPT 策略: " + line,
				Consult:   "[1] cat /etc/sysconfig/iptables",
				Severity:  model.SeveritySuspicious,
				Programme: "vi /etc/sysconfig/iptables # 删除或更改 ACCEPT 配置",
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
			Name:      "HOSTS 安全配置",
			File:      file,
			Info:      "存在境外 IP 设置: " + fields[0],
			Consult:   "[1] cat /etc/hosts",
			Severity:  model.SeveritySuspicious,
			Programme: "vi /etc/hosts # 删除或更改境外 hosts 配置",
			CreatedAt: time.Now(),
		})
	}
	return findings
}
