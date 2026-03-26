package scanners

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Mingcharun/Linux_safescan/gscan-go/internal/scanner"
)

// DiscoverWebRoots finds likely web roots from running services and common defaults.
func DiscoverWebRoots(ctx context.Context) []string {
	commands, err := scanner.RunLines(ctx, "ps", "-axo", "command=")
	if err != nil {
		return []string{"/var/www", "/tmp"}
	}

	roots := []string{"/var/www", "/tmp"}
	for _, cmd := range commands {
		switch {
		case strings.Contains(cmd, "nginx"):
			conf := extractArgValue(cmd, "-c", "/etc/nginx/nginx.conf")
			roots = append(roots, parseNginxRoots(conf)...)
		case strings.Contains(cmd, "httpd"), strings.Contains(cmd, "apache2"):
			conf := extractArgValue(cmd, "-f", "/etc/httpd/conf/httpd.conf")
			roots = append(roots, parseApacheRoots(conf)...)
		case strings.Contains(cmd, "tomcat"):
			if home := extractPrefixValue(cmd, "-Dcatalina.home="); home != "" {
				roots = append(roots, filepath.Join(home, "webapps"), filepath.Join(home, "work"))
			}
			if tmp := extractPrefixValue(cmd, "-Djava.io.tmpdir="); tmp != "" {
				roots = append(roots, tmp)
			}
		case strings.Contains(cmd, "jetty"):
			if home := extractPrefixValue(cmd, "-Djetty.home="); home != "" {
				roots = append(roots, filepath.Join(home, "webapps"), filepath.Join(home, "work"))
			}
			if root := extractPrefixValue(cmd, "-Djetty.webroot="); root != "" {
				roots = append(roots, root)
			}
			if tmp := extractPrefixValue(cmd, "-Djava.io.tmpdir="); tmp != "" {
				roots = append(roots, tmp)
			}
		case strings.Contains(cmd, "resin"):
			if root := extractArgValue(cmd, "--root-directory", ""); root != "" {
				roots = append(roots, filepath.Join(root, "webapps"))
			}
			if conf := extractArgValue(cmd, "-conf", ""); conf != "" {
				roots = append(roots, parseResinRoots(conf)...)
			}
		case strings.Contains(cmd, "jenkins"):
			if root := extractPrefixValue(cmd, "--webroot="); root != "" {
				roots = append(roots, root)
			}
		}
	}

	out := make([]string, 0, len(roots))
	seen := map[string]struct{}{}
	for _, root := range roots {
		root = filepath.Clean(strings.TrimSpace(root))
		if root == "." || root == "" {
			continue
		}
		if _, err := os.Stat(root); err != nil {
			continue
		}
		if _, ok := seen[root]; ok {
			continue
		}
		seen[root] = struct{}{}
		out = append(out, root)
	}
	slices.Sort(out)
	return out
}

func extractArgValue(cmd, flagName, fallback string) string {
	fields := strings.Fields(cmd)
	for i, field := range fields {
		if field == flagName && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return fallback
}

func extractPrefixValue(cmd, prefix string) string {
	for _, field := range strings.Fields(cmd) {
		if strings.HasPrefix(field, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(field, prefix))
		}
	}
	return ""
}

func parseNginxRoots(conf string) []string {
	return parseConfigRoots(conf, []string{"root "}, []string{"include "})
}

func parseApacheRoots(conf string) []string {
	return parseConfigRoots(conf, []string{"DocumentRoot "}, []string{"Include ", "IncludeOptional "})
}

func parseResinRoots(conf string) []string {
	return parseConfigRoots(conf, []string{"root-directory="}, nil)
}

func parseConfigRoots(conf string, rootPrefixes []string, includePrefixes []string) []string {
	info, err := os.Stat(conf)
	if err != nil || info.IsDir() {
		return nil
	}
	fd, err := os.Open(conf)
	if err != nil {
		return nil
	}
	defer fd.Close()

	roots := make([]string, 0)
	sc := bufio.NewScanner(fd)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "<!--") {
			continue
		}
		for _, prefix := range rootPrefixes {
			if strings.HasPrefix(line, prefix) {
				value := strings.Trim(strings.TrimSuffix(strings.TrimPrefix(line, prefix), ";"), `"'`)
				if strings.Contains(line, "root-directory=") && strings.Contains(value, `"`) {
					value = strings.Split(strings.Split(line, `root-directory="`)[1], `"`)[0]
				}
				if value != "" {
					roots = append(roots, value)
				}
			}
		}
		for _, includePrefix := range includePrefixes {
			if strings.HasPrefix(line, includePrefix) {
				pattern := strings.Trim(strings.TrimSuffix(strings.TrimPrefix(line, includePrefix), ";"), `"'`)
				if pattern == "" {
					continue
				}
				matches, _ := filepath.Glob(pattern)
				for _, match := range matches {
					roots = append(roots, parseConfigRoots(match, rootPrefixes, includePrefixes)...)
				}
			}
		}
	}
	return roots
}
