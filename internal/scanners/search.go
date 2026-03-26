package scanners

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mingcharun/Linux_safescan/internal/config"
	"github.com/Mingcharun/Linux_safescan/internal/scanner"
)

// RunSearchMode searches files changed during a given time window.
func RunSearchMode(ctx context.Context, opts config.Options) error {
	parts := strings.Split(opts.TimeRange, "~")
	if len(parts) != 2 {
		return fmt.Errorf("--time must be formatted as 'start~end'")
	}

	lines, err := scanner.RunLines(ctx, "find", "/", "-newermt", strings.TrimSpace(parts[0]), "!", "-newermt", strings.TrimSpace(parts[1]))
	if err != nil {
		return fmt.Errorf("search changed files: %w", err)
	}

	logPath := filepath.Join(opts.OutputRoot, "log", "search.log")
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(logPath, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		return err
	}

	fmt.Printf("时间周期: %s\n搜索结果: 共发现 %d 处文件或目录发生创建和改动\n结果详情: %s\n", opts.TimeRange, len(lines), logPath)
	return nil
}
