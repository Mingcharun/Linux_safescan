# GScan Go

这是对原始 [GScan](../GScan) 的 Go 重构版第一阶段工程。

当前目标不是做一个“外观像 Go 的单文件脚本”，而是把原来耦合在 Python 插件里的逻辑，重组为可测试、可迭代、可继续增强的 Go 模块。

## 当前已完成

- CLI 参数骨架：`--full`、`--dif`、`--sug`、`--pro`、`--time`、`--job`
- 规则库加载：复用原项目 `lib/malware` 文本规则
- 17mon GeoIP 离线库读取：复用原项目 `17monipdb.dat`
- 已迁移扫描器：
  - 系统初始化 alias 检查
  - 历史命令扫描
  - 文件类扫描与系统二进制 hash 基线
  - 进程类扫描
  - 网络类扫描
  - 常规后门扫描
  - 账户类扫描
  - 配置类扫描
  - 登录日志扫描
- 报告输出：
  - `runtime/log/gscan.log`
  - `runtime/db/findings.json`
  - `runtime/db/findings_hashes.txt`
  - `runtime/db/system_hashes.txt`

## 暂未迁移

- Rootkit 全量特征库迁移
- Webshell YARA 扫描
- 原版数据聚合文案的完整复刻
- 定时任务的自动写入系统 crontab

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
go run ./cmd/gscan --time="2026-03-20 00:00:00~2026-03-20 23:59:59"
```

如果你当前目录结构和本工作区一致，程序会默认复用：

- `../GScan/lib/malware`
- `../GScan/lib/core/ip/17monipdb.dat`

也可以手动指定：

```bash
go run ./cmd/gscan --rules-dir=/path/to/malware --geoip-db=/path/to/17monipdb.dat
```
