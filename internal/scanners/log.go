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

type logScanner struct{}

// NewLogScanner creates the login log scanner.
func NewLogScanner() scanner.Runner { return &logScanner{} }

func (s *logScanner) Name() string { return "Login Log Analysis" }

func (s *logScanner) Run(ctx context.Context, rt *scanner.Runtime) ([]model.Finding, error) {
	findings := make([]model.Finding, 0)
	findings = append(findings, s.scanWho(ctx, rt, "/var/log/wtmp", "wtmp login history")...)
	findings = append(findings, s.scanWho(ctx, rt, "", "utmp login history")...)
	findings = append(findings, s.scanLastlog(ctx, rt)...)
	findings = append(findings, s.scanSecure(rt)...)
	return findings, nil
}

func (s *logScanner) scanWho(ctx context.Context, rt *scanner.Runtime, file string, name string) []model.Finding {
	args := []string{}
	if file != "" {
		args = append(args, file)
	}
	lines, err := scanner.RunLines(ctx, "who", args...)
	if err != nil {
		return nil
	}
	findings := make([]model.Finding, 0)
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		user := fields[0]
		when := fields[2]
		host := strings.Trim(fields[len(fields)-1], "()")
		if !rt.IsForeignIP(host) {
			continue
		}
		findings = append(findings, model.Finding{
			Category:  s.Name(),
			Name:      name,
			File:      file,
			Time:      when,
			User:      user,
			Info:      "Foreign IP logged in as " + user + ": " + host,
			Consult:   "[1] who",
			Severity:  model.SeveritySuspicious,
			Programme: "passwd " + user + " # rotate credential",
			CreatedAt: time.Now(),
		})
	}
	return findings
}

func (s *logScanner) scanLastlog(ctx context.Context, rt *scanner.Runtime) []model.Finding {
	lines, err := scanner.RunLines(ctx, "lastlog")
	if err != nil {
		return nil
	}
	findings := make([]model.Finding, 0)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		user := fields[0]
		ip := fields[1]
		if !rt.IsForeignIP(ip) {
			continue
		}
		findings = append(findings, model.Finding{
			Category:  s.Name(),
			Name:      "lastlog login history",
			File:      "/var/log/lastlog",
			User:      user,
			Info:      "Foreign IP logged in as " + user + ": " + ip,
			Consult:   "[1] lastlog",
			Severity:  model.SeveritySuspicious,
			Programme: "passwd " + user + " # rotate credential",
			CreatedAt: time.Now(),
		})
	}
	return findings
}

func (s *logScanner) scanSecure(rt *scanner.Runtime) []model.Finding {
	for _, path := range []string{"/var/log/secure", "/var/log/auth.log"} {
		fd, err := os.Open(path)
		if err != nil {
			continue
		}
		defer fd.Close()

		findings := make([]model.Finding, 0)
		pattern := regexp.MustCompile(`Accepted .* for (\S+) from ((?:\d{1,3}\.){3}\d{1,3})`)
		sc := bufio.NewScanner(fd)
		for sc.Scan() {
			line := sc.Text()
			match := pattern.FindStringSubmatch(line)
			if len(match) != 3 || !rt.IsForeignIP(match[2]) {
				continue
			}
				findings = append(findings, model.Finding{
				Category:  s.Name(),
					Name:      "secure log review",
				File:      path,
				User:      match[1],
					Info:      "Successful SSH login from external address: " + strings.TrimSpace(line),
				Consult:   "[1] cat " + path,
				Severity:  model.SeverityRisk,
					Programme: "passwd " + match[1] + " # rotate credential",
				CreatedAt: time.Now(),
			})
		}
		return findings
	}
	return nil
}
