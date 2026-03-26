# Linux Safescan

作者：`Mingcha_run`

仓库地址：[https://github.com/Mingcharun/Linux_safescan](https://github.com/Mingcharun/Linux_safescan)

这是对原始 GScan 的 Go 重构版。当前版本已经不再只是骨架，而是一个可运行、可扩展、可继续增强的 Linux 主机应急扫描工具，并且规则与离线库已经内置到当前项目。

## 当前已完成

- CLI 能力：`--full`、`--dif`、`--sug`、`--pro`、`--time`、`--job`、`--log`
- 规则库加载：内置 `assets/malware` 文本规则
- 17mon GeoIP 离线库读取：内置 `assets/geoip/17monipdb.dat`
- Rootkit 规则复用：默认加载 `assets/rootkits.json`，兼容旧版 `Rootkit_Analysis.py`
- Webshell 规则复用：内置 `assets/webshell_rule/*.yar`
- 已迁移扫描器：
  - 主机信息获取
  - 系统初始化 alias 检查
  - 历史命令扫描
  - 文件类扫描与系统二进制 hash 基线
  - 进程类扫描
  - 网络类扫描
  - 常规后门扫描
  - 账户类扫描
  - 配置类扫描
  - 登录日志扫描
  - Rootkit 扫描
  - Webshell 扫描
- 辅助能力：
  - 差异扫描哈希
  - 中文文本报告
  - JSON 结果输出
  - Web 根目录发现
  - 定时任务写入 `crontab`
  - 常见安全日志打包
- 报告输出：
  - `runtime/log/gscan.log`
  - `runtime/db/findings.json`
  - `runtime/db/findings_hashes.txt`
  - `runtime/db/system_hashes.txt`

## 当前仍有边界

- 目标运行环境仍以 Linux 主机为主，macOS 上只能做有限验证
- Webshell 规则引擎是轻量 Go 解析器，不是完整 libyara 运行时
- 报告文案已迁移为中文时间线，但没有逐字复刻旧版输出格式

## 使用方式

在 `gscan-go` 目录中执行：

```bash
go run ./cmd/gscan
```

常见模式：

```bash
go run ./cmd/gscan --full
go run ./cmd/gscan --dif
go run ./cmd/gscan --sug --pro
go run ./cmd/gscan --job --hour=2
go run ./cmd/gscan --log
go run ./cmd/gscan --time="2026-03-20 00:00:00~2026-03-20 23:59:59"
```

默认情况下程序直接使用当前项目内置资产：

- `assets/malware`
- `assets/geoip/17monipdb.dat`
- `assets/rootkits.json`
- `assets/webshell_rule`

也可以手动指定：

```bash
go run ./cmd/gscan \
  --rules-dir=/path/to/malware \
  --geoip-db=/path/to/17monipdb.dat \
  --rootkit-source=/path/to/rootkits.json \
  --webshell-rules=/path/to/webshell_rule
```
