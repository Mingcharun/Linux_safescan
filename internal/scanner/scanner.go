package scanner

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Mingcharun/Linux_safescan/internal/config"
	"github.com/Mingcharun/Linux_safescan/internal/geoip"
	"github.com/Mingcharun/Linux_safescan/internal/model"
	"github.com/Mingcharun/Linux_safescan/internal/rules"
)

// Runner is the contract implemented by each scanning module.
type Runner interface {
	Name() string
	Run(ctx context.Context, rt *Runtime) ([]model.Finding, error)
}

// Runtime provides shared capabilities to scanners.
type Runtime struct {
	Options  config.Options
	Rules    *rules.Corpus
	GeoIP    *geoip.IPv4Database
	Host     model.HostInfo
	Warnings []string
}

var (
	ipHTTPPattern = regexp.MustCompile(`(?i)(htt|ft)p(s)?://(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)`)
	ipPattern     = regexp.MustCompile(`(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)`)
)

// Warn records a non-fatal runtime warning.
func (rt *Runtime) Warn(format string, args ...any) {
	rt.Warnings = append(rt.Warnings, fmt.Sprintf(format, args...))
}

// AnalyzeText returns a suspicious description if the snippet matches known behaviors.
func (rt *Runtime) AnalyzeText(content string) string {
	content = strings.Join(strings.Fields(strings.TrimSpace(content)), " ")
	if content == "" {
		return ""
	}
	if CheckShell(content) {
		return "反弹 shell 类: " + content
	}
	if rt.ContainsForeignIP(content) {
		return "境外 IP 操作类: " + content
	}
	return ""
}

// AnalyzeFile checks whether a file contains known suspicious strings.
func (rt *Runtime) AnalyzeFile(path string) string {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return ""
	}
	if info.Size() == 0 || info.Size() > 10*1024*1024 {
		return ""
	}

	base := filepath.Base(path)
	cleanPath := filepath.ToSlash(path)
	switch {
	case strings.Contains(cleanPath, "/.git/"),
		strings.Contains(cleanPath, "/assets/"),
		strings.Contains(cleanPath, "/runtime/"),
		strings.HasSuffix(strings.ToLower(cleanPath), ".jpg"),
		strings.HasSuffix(strings.ToLower(cleanPath), ".log"),
		strings.Contains(cleanPath, " "):
		return ""
	}
	if base == "" {
		return ""
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	stringsFound := ExtractStrings(data, 4, 256)
	if len(stringsFound) > 200 {
		return ""
	}
	for _, s := range stringsFound {
		if CheckShell(s) {
			return "反弹 shell 类: " + s
		}
		if rt.Options.Full {
			if indicator := rt.Rules.Match(s); indicator != "" {
				return fmt.Sprintf("恶意特征类: %s, 匹配规则: %s", s, indicator)
			}
		}
		if rt.ContainsForeignIP(s) {
			return "境外 IP 操作类: " + s
		}
	}
	return ""
}

// ContainsForeignIP checks whether content references a non-China public IPv4.
func (rt *Runtime) ContainsForeignIP(content string) bool {
	if rt.Options.SkipForeignIP || !ipHTTPPattern.MatchString(content) {
		return false
	}
	for _, ip := range ipPattern.FindAllString(content, -1) {
		if rt.IsForeignIP(ip) {
			return true
		}
	}
	return false
}

// IsForeignIP returns true when the IP is public and resolves outside China.
func (rt *Runtime) IsForeignIP(raw string) bool {
	if rt.Options.SkipForeignIP {
		return false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || !addr.Is4() || !addr.IsValid() || addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsMulticast() {
		return false
	}
	location := rt.GeoIP.Find(addr.String())
	if location == "" {
		return false
	}
	return !(strings.HasPrefix(location, "中国") ||
		strings.HasPrefix(location, "局域网") ||
		strings.HasPrefix(location, "共享地址") ||
		strings.HasPrefix(location, "本机地址") ||
		strings.HasPrefix(location, "本地链路") ||
		strings.HasPrefix(location, "保留地址"))
}

// CheckShell detects reverse shell or download-and-exec content.
func CheckShell(content string) bool {
	content = strings.TrimSpace(content)
	switch {
	case strings.Contains(content, "bash") && (strings.Contains(content, "/dev/tcp/") ||
		strings.Contains(content, "telnet ") ||
		strings.Contains(content, "nc ") ||
		(strings.Contains(content, "exec ") && strings.Contains(content, "socket")) ||
		strings.Contains(content, "curl ") ||
		strings.Contains(content, "wget ") ||
		strings.Contains(content, "lynx ") ||
		strings.Contains(content, "bash -i")):
		return true
	case strings.Contains(content, ".decode('base64')") || strings.Contains(content, "exec(base64.b64decode"):
		return true
	case strings.Contains(content, "/dev/tcp/") && (strings.Contains(content, "exec ") || strings.Contains(content, "ksh -c")):
		return true
	case strings.Contains(content, "exec ") && (strings.Contains(content, "socket.") || strings.Contains(content, ".decode('base64')")):
		return true
	case (strings.Contains(content, "wget ") || strings.Contains(content, "curl ")) &&
		(strings.Contains(content, " -O ") || strings.Contains(content, " -s ")) &&
		strings.Contains(content, " http") &&
		(strings.Contains(content, "php ") || strings.Contains(content, "perl") || strings.Contains(content, "python ") || strings.Contains(content, "sh ") || strings.Contains(content, "bash ")):
		return true
	default:
		return false
	}
}

// ExtractStrings extracts printable strings from a binary blob.
func ExtractStrings(data []byte, minLen int, maxLen int) []string {
	out := make([]string, 0, 32)
	var current []byte
	flush := func() {
		if len(current) >= minLen {
			out = append(out, string(current))
		}
		current = current[:0]
	}

	for _, b := range data {
		if (b >= 32 && b <= 126) || b == '\t' {
			if maxLen <= 0 || len(current) < maxLen {
				current = append(current, b)
			}
			continue
		}
		flush()
	}
	flush()

	return out
}

// WalkFiles recursively visits regular files under root.
func WalkFiles(root string, fn func(path string, info os.FileInfo) error) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		return fn(path, info)
	})
}

// RunLines executes a command and returns split output lines.
func RunLines(ctx context.Context, name string, args ...string) ([]string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil, nil
	}
	return lines, nil
}

// FileMeta returns file mtime and owner name.
func FileMeta(path string) (string, string) {
	info, err := os.Stat(path)
	if err != nil {
		return "", ""
	}
	mtime := info.ModTime().Format("2006-01-02 15:04:05")
	return mtime, fileOwner(info)
}

// ParsePIDCommand tries to split "123/proc" values safely.
func ParsePIDCommand(raw string) (string, string) {
	parts := strings.SplitN(strings.TrimSpace(raw), "/", 2)
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}

// MustTime formats timestamps in the legacy report style.
func MustTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02 15:04:05")
}

// ParsePercent turns ps percentage strings into numbers.
func ParsePercent(raw string) float64 {
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return 0
	}
	return value
}

// IsELF reports whether the file begins with an ELF magic header.
func IsELF(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	buf := make([]byte, 4)
	if _, err := file.Read(buf); err != nil {
		return false
	}
	return string(buf) == "\x7fELF"
}

type processRecord struct {
	User string
	PID  string
	CPU  float64
	MEM  float64
	Cmd  string
}

// ListProcesses returns parsed `ps` output.
func ListProcesses(ctx context.Context) ([]processRecord, error) {
	lines, err := RunLines(ctx, "ps", "-axo", "user=,pid=,pcpu=,pmem=,command=")
	if err != nil {
		return nil, err
	}
	out := make([]processRecord, 0, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		out = append(out, processRecord{
			User: fields[0],
			PID:  fields[1],
			CPU:  ParsePercent(fields[2]),
			MEM:  ParsePercent(fields[3]),
			Cmd:  strings.Join(fields[4:], " "),
		})
	}
	return out, nil
}

// ProbeOutboundIP returns the preferred outbound IP if available.
func ProbeOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ""
	}
	return addr.IP.String()
}
