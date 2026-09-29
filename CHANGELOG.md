# 更新日志

本文件记录 `wist-gateway` 的所有重要变更。格式遵循 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## [0.1.7-alpha] - 2026-09-29

### 变更

- **内置 agent 安装包改为可选**：`agent.package_file` 为空、或指向的文件不存在，都**不再阻断启动**
  （只在日志里留一条告警）。以前一个包里缺失的安装包会让整个控制面起不来。
  真正用到它的端点会在被调用时明确报错：安装脚本 / 签名 → `500 未配置 agent 安装包…`；
  `/api/v1/agent/packages/current` 无可用包 → `503`。
