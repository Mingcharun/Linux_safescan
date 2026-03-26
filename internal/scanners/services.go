package scanners

import (
	"context"
	"regexp"
	"strings"

	"github.com/Mingcharun/Linux_safescan/internal/scanner"
)

// DiscoverOpenServices returns listening services from ss output.
func DiscoverOpenServices(ctx context.Context) []string {
	lines, err := scanner.RunLines(ctx, "ss", "-lntpH")
	if err != nil {
		return nil
	}
	pidPattern := regexp.MustCompile(`pid=(\d+)`)
	procPattern := regexp.MustCompile(`"([^"]+)"`)
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		local := fields[3]
		pid := ""
		proc := ""
		if match := pidPattern.FindStringSubmatch(line); len(match) == 2 {
			pid = match[1]
		}
		if match := procPattern.FindStringSubmatch(line); len(match) == 2 {
			proc = match[1]
		}
		out = append(out, strings.TrimSpace(local+" "+proc+" "+pid))
	}
	return out
}
