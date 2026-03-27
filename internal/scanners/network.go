package scanners

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Mingcharun/Linux_safescan/internal/model"
	"github.com/Mingcharun/Linux_safescan/internal/scanner"
)

type networkScanner struct{}

// NewNetworkScanner creates the network scanner.
func NewNetworkScanner() scanner.Runner { return &networkScanner{} }

func (s *networkScanner) Name() string { return "Network Activity" }

func (s *networkScanner) Run(ctx context.Context, rt *scanner.Runtime) ([]model.Finding, error) {
	conns := establishedConnections(ctx)
	findings := make([]model.Finding, 0)
	for _, conn := range conns {
		if rt.IsForeignIP(conn.RemoteIP) {
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "Foreign IP connection",
				PID:       conn.PID,
				Info:      fmt.Sprintf("Process %s established %s to foreign IP %s", conn.Process, conn.Protocol, conn.RemoteIP),
				Consult:   "[1] ss -antp",
				Severity:  model.SeveritySuspicious,
				Programme: "kill " + conn.PID + " # terminate process",
				CreatedAt: time.Now(),
			})
		}
		if description, ok := suspiciousPorts()[conn.RemotePort]; ok {
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "Suspicious remote port",
				PID:       conn.PID,
				Info:      fmt.Sprintf("Process %s connected to %s:%s (typically used by %s)", conn.Process, conn.RemoteIP, conn.RemotePort, description),
				Consult:   "[1] ss -antp",
				Severity:  model.SeveritySuspicious,
				Programme: "kill " + conn.PID + " # terminate process",
				CreatedAt: time.Now(),
			})
		}
	}

	if lines, err := scanner.RunLines(ctx, "ip", "-o", "link", "show"); err == nil {
		for _, line := range lines {
			if strings.Contains(line, "PROMISC") {
				findings = append(findings, model.Finding{
					Category:  s.Name(),
					Name:      "NIC promiscuous mode",
					Info:      "Interface in promiscuous mode: " + line,
					Consult:   "ip -o link show",
					Severity:  model.SeveritySuspicious,
					Programme: "ip link set dev eth0 promisc off # disable promiscuous mode",
					CreatedAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

type connection struct {
	Protocol   string
	RemoteIP   string
	RemotePort string
	PID        string
	Process    string
}

func establishedConnections(ctx context.Context) []connection {
	lines, err := scanner.RunLines(ctx, "ss", "-antpH")
	if err != nil {
		return nil
	}
	pidPattern := regexp.MustCompile(`pid=(\d+)`)
	procPattern := regexp.MustCompile(`"([^"]+)"`)
	out := make([]connection, 0)
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 || !strings.Contains(fields[0], "ESTAB") {
			continue
		}
		remoteIP, remotePort := splitAddr(fields[4])
		pid := ""
		proc := ""
		if match := pidPattern.FindStringSubmatch(line); len(match) == 2 {
			pid = match[1]
		}
		if match := procPattern.FindStringSubmatch(line); len(match) == 2 {
			proc = match[1]
		}
		out = append(out, connection{
			Protocol:   "tcp",
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
			PID:        pid,
			Process:    proc,
		})
	}
	return out
}

func splitAddr(raw string) (string, string) {
	idx := strings.LastIndex(raw, ":")
	if idx == -1 {
		return raw, ""
	}
	return strings.Trim(raw[:idx], "[]"), raw[idx+1:]
}

func suspiciousPorts() map[string]string {
	return map[string]string{
		"1524":  "Possible FreeBSD (FBRK) Rootkit backdoor",
		"1984":  "Fuckit Rootkit",
		"2001":  "Scalper",
		"2006":  "CB Rootkit or w00tkit Rootkit SSH server",
		"2128":  "MRK",
		"6666":  "Possible rogue IRC bot",
		"6667":  "Possible rogue IRC bot",
		"6668":  "Possible rogue IRC bot",
		"6669":  "Possible rogue IRC bot",
		"7000":  "Possible rogue IRC bot",
		"13000": "Possible Universal Rootkit (URK) SSH server",
		"14856": "Optic Kit (Tux)",
		"25000": "Possible Universal Rootkit (URK) component",
		"29812": "FreeBSD (FBRK) Rootkit default backdoor port",
		"31337": "Historical backdoor port",
		"32982": "Solaris Wanuk",
		"33369": "Volc Rootkit SSH server (divine)",
		"47018": "Possible Universal Rootkit (URK) component",
		"47107": "T0rn",
		"60922": "zaRwT.KiT",
		"62883": "Possible FreeBSD (FBRK) Rootkit default backdoor port",
		"65535": "FreeBSD Rootkit (FBRK) telnet port",
	}
}
