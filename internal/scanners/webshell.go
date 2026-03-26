package scanners

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mingcharun/Linux_safescan/internal/model"
	"github.com/Mingcharun/Linux_safescan/internal/rules"
	"github.com/Mingcharun/Linux_safescan/internal/scanner"
)

type webshellScanner struct{}

// NewWebshellScanner creates the webshell scanner.
func NewWebshellScanner() scanner.Runner { return &webshellScanner{} }

func (s *webshellScanner) Name() string { return "Webshell安全检测" }

func (s *webshellScanner) Run(ctx context.Context, rt *scanner.Runtime) ([]model.Finding, error) {
	corpus, err := rules.LoadYaraLite(rt.Options.WebshellRules)
	if err != nil {
		return nil, err
	}
	if corpus == nil || len(corpus.Rules) == 0 {
		return nil, nil
	}

	roots := DiscoverWebRoots(ctx)
	findings := make([]model.Finding, 0)
	for _, root := range roots {
		_ = scanner.WalkFiles(root, func(path string, info os.FileInfo) error {
			if info.Size() == 0 || info.Size() > 10*1024*1024 || !looksLikeWebContent(path) {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			matches := corpus.Match(data)
			if len(matches) == 0 {
				return nil
			}
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "webshell 安全检测",
				File:      path,
				Info:      "文件匹配到 webshell 规则: " + strings.Join(matches, ", "),
				Consult:   "[1] cat " + path,
				Severity:  model.SeverityRisk,
				Programme: "rm " + path + " # 删除 webshell 文件",
				CreatedAt: time.Now(),
			})
			return nil
		})
	}
	return findings, nil
}

func looksLikeWebContent(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".php", ".phtml", ".jsp", ".jspx", ".asp", ".aspx", ".cfm", ".war", ".xml", ".js", ".html", ".htm", ".jpg", ".jpeg", ".gif", ".png", ".txt":
		return true
	default:
		return false
	}
}
