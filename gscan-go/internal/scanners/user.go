package scanners

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/grayddq/gscan-go/internal/model"
	"github.com/grayddq/gscan-go/internal/scanner"
)

type userScanner struct{}

// NewUserScanner creates the account scanner.
func NewUserScanner() scanner.Runner { return &userScanner{} }

func (s *userScanner) Name() string { return "账户类安全检测" }

func (s *userScanner) Run(ctx context.Context, rt *scanner.Runtime) ([]model.Finding, error) {
	_ = ctx
	findings := make([]model.Finding, 0)
	findings = append(findings, s.scanPasswd()...)
	findings = append(findings, s.scanShadow()...)
	findings = append(findings, s.scanSudoers()...)
	findings = append(findings, s.scanAuthorizedKeys()...)
	findings = append(findings, s.scanPasswordFilePerms()...)
	return findings, nil
}

func (s *userScanner) scanPasswd() []model.Finding {
	fd, err := os.Open("/etc/passwd")
	if err != nil {
		return nil
	}
	defer fd.Close()

	findings := make([]model.Finding, 0)
	sc := bufio.NewScanner(fd)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) < 7 {
			continue
		}
		user := fields[0]
		uid := fields[2]
		gid := fields[3]
		shell := fields[6]
		if uid == "0" && user != "root" {
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "root 权限账户安全扫描",
				File:      "/etc/passwd",
				User:      user,
				Info:      "存在特权用户 " + user,
				Consult:   "[1] cat /etc/passwd",
				Severity:  model.SeveritySuspicious,
				Programme: "vi /etc/passwd # 删除用户 root 权限",
				CreatedAt: time.Now(),
			})
		}
		if gid == "0" && user != "root" && strings.Contains(shell, "/bin/bash") {
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "特权组账户安全扫描",
				File:      "/etc/passwd",
				User:      user,
				Info:      "存在特权组用户 " + user,
				Consult:   "[1] cat /etc/passwd",
				Severity:  model.SeveritySuspicious,
				Programme: "vi /etc/passwd # 删除特权组或删除用户",
				CreatedAt: time.Now(),
			})
		}
	}
	return findings
}

func (s *userScanner) scanShadow() []model.Finding {
	fd, err := os.Open("/etc/shadow")
	if err != nil {
		return nil
	}
	defer fd.Close()

	findings := make([]model.Finding, 0)
	sc := bufio.NewScanner(fd)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) < 2 {
			continue
		}
		if fields[1] == "" {
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "空口令账户安全扫描",
				File:      "/etc/shadow",
				User:      fields[0],
				Info:      "存在空口令用户 " + fields[0],
				Consult:   "[1] cat /etc/shadow",
				Severity:  model.SeverityRisk,
				Programme: "userdel " + fields[0] + " # 删除空口令用户",
				CreatedAt: time.Now(),
			})
		}
	}
	return findings
}

func (s *userScanner) scanSudoers() []model.Finding {
	fd, err := os.Open("/etc/sudoers")
	if err != nil {
		return nil
	}
	defer fd.Close()

	findings := make([]model.Finding, 0)
	sc := bufio.NewScanner(fd)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "%") {
			continue
		}
		if strings.Contains(line, "ALL=(ALL)") {
			user := strings.Fields(line)[0]
			if user == "root" {
				continue
			}
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "sudoers 权限安全扫描",
				File:      "/etc/sudoers",
				User:      user,
				Info:      fmt.Sprintf("用户 %s 可通过 sudo 命令获取特权", user),
				Consult:   "[1] cat /etc/sudoers",
				Severity:  model.SeverityRisk,
				Programme: "vi /etc/sudoers # 更改 sudo 设置",
				CreatedAt: time.Now(),
			})
		}
	}
	return findings
}

func (s *userScanner) scanAuthorizedKeys() []model.Finding {
	findings := make([]model.Finding, 0)
	files := []string{"/root/.ssh/authorized_keys"}
	for _, root := range []string{"/home"} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			files = append(files, filepath.Join(root, entry.Name(), ".ssh", "authorized_keys"))
		}
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil || len(data) == 0 {
			continue
		}
		keys := make([]string, 0)
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) >= 3 {
				keys = append(keys, fields[2])
			}
		}
		findings = append(findings, model.Finding{
			Category:  s.Name(),
			Name:      "账户免密码证书安全扫描",
			File:      file,
			Info:      "存在免密登录证书，证书客户端名称: " + strings.Join(keys, " & "),
			Consult:   "[1] cat " + file,
			Severity:  model.SeveritySuspicious,
			Programme: "vi " + file + " # 删除证书设置",
			CreatedAt: time.Now(),
		})
	}
	return findings
}

func (s *userScanner) scanPasswordFilePerms() []model.Finding {
	findings := make([]model.Finding, 0)
	for _, path := range []string{"/etc/passwd", "/etc/shadow"} {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		mode := info.Mode().String()
		if path == "/etc/passwd" && mode != "-rw-r--r--" {
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "账户密码文件扫描",
				File:      path,
				Info:      "passwd 文件权限变更，不为 -rw-r--r--",
				Consult:   "ls -l /etc/passwd",
				Severity:  model.SeveritySuspicious,
				CreatedAt: time.Now(),
			})
		}
		if path == "/etc/shadow" && mode != "----------" {
			findings = append(findings, model.Finding{
				Category:  s.Name(),
				Name:      "账户密码文件扫描",
				File:      path,
				Info:      "shadow 文件权限变更，不为 ----------",
				Consult:   "ls -l /etc/shadow",
				Severity:  model.SeveritySuspicious,
				CreatedAt: time.Now(),
			})
		}
	}
	return findings
}
