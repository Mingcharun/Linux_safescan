package app

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mingcharun/Linux_safescan/gscan-go/internal/config"
)

func installCrontab(_ context.Context, opts config.Options) error {
	line := cronLine()
	current := ""
	if out, err := exec.Command("crontab", "-l").CombinedOutput(); err == nil {
		current = string(out)
	}
	if strings.Contains(current, line) {
		fmt.Println("定时任务已存在，无需重复写入。")
		return nil
	}

	var buf bytes.Buffer
	if strings.TrimSpace(current) != "" {
		buf.WriteString(strings.TrimRight(current, "\n"))
		buf.WriteString("\n")
	}
	buf.WriteString(line)
	buf.WriteString("\n")

	cmd := exec.Command("crontab", "-")
	cmd.Stdin = &buf
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("write crontab: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	fmt.Println("定时任务写入成功。")
	return nil
}

func cronLine() string {
	exe, err := os.Executable()
	if err != nil {
		exe = "./gscan"
	}
	if strings.Contains(exe, "go-build") {
		cwd, _ := os.Getwd()
		exe = filepath.Join(cwd, "gscan")
	}
	if strings.TrimSpace(exe) == "" {
		exe = "./gscan"
	}
	if hour := currentHour(); hour > 0 {
		return fmt.Sprintf("* */%d * * * %s --dif", hour, exe)
	}
	return fmt.Sprintf("0 0 * * * %s --dif", exe)
}

var scheduledHour int

func currentHour() int {
	return scheduledHour
}

func backupLogs(outputRoot string) error {
	targetDir := filepath.Join(outputRoot, "log")
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return err
	}
	archivePath := filepath.Join(targetDir, "security-logs-"+time.Now().Format("20060102-150405")+".tar.gz")
	file, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()

	gw := gzip.NewWriter(file)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	for _, path := range logCandidates() {
		_ = addPathToTar(tw, path)
	}
	fmt.Printf("安全日志已打包到 %s\n", archivePath)
	return nil
}

func logCandidates() []string {
	return []string{
		"/var/log/secure",
		"/var/log/messages",
		"/var/log/auth.log",
		"/var/log/wtmp",
		"/var/log/utmp",
		"/var/log/lastlog",
		"/var/log/nginx",
		"/var/log/httpd",
		"/var/log/apache2",
	}
}

func addPathToTar(tw *tar.Writer, root string) error {
	info, err := os.Stat(root)
	if err != nil {
		return nil
	}
	if !info.IsDir() {
		return writeFileToTar(tw, root, info)
	}
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		return writeFileToTar(tw, path, info)
	})
}

func writeFileToTar(tw *tar.Writer, path string, info os.FileInfo) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return nil
	}
	header.Name = strings.TrimPrefix(path, "/")
	if err := tw.WriteHeader(header); err != nil {
		return nil
	}
	_, _ = tw.Write(data)
	return nil
}
