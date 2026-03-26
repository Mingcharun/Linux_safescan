# <div align="center">Linux Safescan</div>

<div align="center">

**A pure Go Linux incident response scanner built for fast triage, rule-based detection, and readable host reports.**

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=for-the-badge&logo=go)](https://go.dev/)
[![Platform](https://img.shields.io/badge/Platform-Linux-2F855A?style=for-the-badge&logo=linux)](#quick-start)
[![License](https://img.shields.io/badge/License-Open%20Source-111827?style=for-the-badge)](#license)
[![Repo](https://img.shields.io/badge/GitHub-Mingcharun%2FLinux__safescan-181717?style=for-the-badge&logo=github)](https://github.com/Mingcharun/Linux_safescan)

</div>

> 面向 Linux 主机应急响应与安全巡检场景的开源工具。  
> 当前版本已完成从旧版 Python GScan 到 Go 的重构，并且仓库根目录现在就是主工程目录。

## Overview

Linux Safescan 提供一套可直接落地的主机侧扫描能力：

- IOC 文本规则扫描
- 进程、网络、账户、配置、日志、后门、Rootkit、Webshell 检查
- 系统关键文件哈希基线与差异比较
- 离线 GeoIP 判断境外 IP 线索
- 中文文本报告与 JSON 结构化结果输出
- `crontab` 定时扫描与常见安全日志打包

## Highlights

| Capability | Status | Notes |
| --- | --- | --- |
| IOC rules | Ready | 内置 `assets/malware` 规则库 |
| GeoIP | Ready | 内置 `assets/geoip/17monipdb.dat` |
| Rootkit scan | Ready | 默认加载 `assets/rootkits.json`，兼容旧版 Python 规则源 |
| Webshell scan | Ready | 内置 `assets/webshell_rule/*.yar` 轻量规则引擎 |
| Diff mode | Ready | 对比上次结果，仅输出新增异常 |
| Host report | Ready | 输出中文日志和 JSON 结果 |
| Scheduled run | Ready | 生成/写入定时执行项 |

## Quick Start

### 1. Run directly

```bash
go run ./cmd/gscan
```

### 2. Common modes

```bash
go run ./cmd/gscan --full
go run ./cmd/gscan --dif
go run ./cmd/gscan --sug --pro
go run ./cmd/gscan --job --hour=2
go run ./cmd/gscan --log
go run ./cmd/gscan --time="2026-03-20 00:00:00~2026-03-20 23:59:59"
```

### 3. Build binary

```bash
go build -o gscan ./cmd/gscan
./gscan --version
```

## Built-in Assets

仓库已经内置扫描所需核心资产，开箱可用：

- `assets/malware`
- `assets/geoip/17monipdb.dat`
- `assets/rootkits.json`
- `assets/webshell_rule`

如果你有自定义规则，也可以在运行时覆盖：

```bash
go run ./cmd/gscan \
  --rules-dir=/path/to/malware \
  --geoip-db=/path/to/17monipdb.dat \
  --rootkit-source=/path/to/rootkits.json \
  --webshell-rules=/path/to/webshell_rule
```

## CLI Flags

| Flag | Description |
| --- | --- |
| `--full` | 启用完整 IOC 匹配扫描 |
| `--dif` | 仅输出相对上次扫描新增的异常 |
| `--sug` | 在报告中附加调查建议 |
| `--pro` | 在报告中附加初始处置建议 |
| `--time` | 按时间范围检索改动文件 |
| `--job --hour=N` | 写入定时扫描计划 |
| `--log` | 打包常见安全日志 |
| `--overseas` | 跳过境外 IP 识别 |
| `--disable-log-scan` | 禁用登录日志分析 |
| `--disable-webshell` | 禁用 Webshell 扫描 |
| `--disable-rootkit` | 禁用 Rootkit 扫描 |

## Output

默认输出目录为 `runtime/`，关键文件包括：

```text
runtime/
├── db/
│   ├── findings.json
│   ├── findings_hashes.txt
│   └── system_hashes.txt
└── log/
    └── gscan.log
```

## Project Layout

```text
.
├── assets/        # 内置规则、GeoIP、Rootkit/Webshell 资产
├── cmd/gscan/     # CLI 入口
├── docs/          # 补充设计文档与路线图
├── internal/      # 扫描器、规则加载、报告与基础设施
└── README.md
```

## Validation

当前仓库已经过以下校验：

```bash
go vet ./...
go test ./...
go test -race ./...
go run ./cmd/gscan --version
```

> 说明：当前开发机是 macOS，代码级验证已完成；完整主机扫描回归应在 Linux 目标环境执行。

## Roadmap

- 完善 Linux 实机回归样本
- 收敛误报并提升报告可读性
- 继续增强规则来源与扩展能力

详细规划见 [`docs/ROADMAP_CN.md`](docs/ROADMAP_CN.md)。

## Author

- ID: `Mingcha_run`
- GitHub: [Mingcharun](https://github.com/Mingcharun)

## License

开源发布前建议你补充明确的许可证文件。当前仓库尚未添加 `LICENSE`。
