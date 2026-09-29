# CloudLeak Sentinel v0.6 技术设计

## 1. 数据流

Source Plugin → Artifact Normalization → Incremental Cache → Credential Detection → Risk Engine → Allowlist → Dedup → Event Store → Alert / Dashboard。

异步模式在 Source Plugin 前增加持久化 Job Queue。服务进程重启后，处于 running 的任务重新置为 queued。

## 2. 检测

检测信号包括：提供商专用格式、通用 Secret Assignment、Shannon entropy、敏感上下文、敏感路径、AK/SK 同对象关联、placeholder/test 标记和 Git 历史状态。

数据库连接串只有检测到 `scheme://user:password@host/...` 形式的认证信息时才进入凭据事件，避免把普通无密码 URI 当作泄露。

## 3. 增量扫描

每个规范化 Artifact 使用 `SHA-256(content)` 建立 `(source, locator)` 内容缓存。扫描开始时一次性加载缓存索引，扫描结束后批量 UPSERT，避免每个 Artifact 单独打开 SQLite 连接。异步普通任务若内容未变化，则跳过检测并累计 `skipped_unchanged`。Git add/remove 生命周期对象不走该跳过逻辑，以免破坏时序语义。

## 4. 任务队列

SQLite `jobs` 表记录 queued/running/done/error。worker 使用 `BEGIN IMMEDIATE` 原子 claim，默认两个并发 worker，最大四个。进度字段包括 processed / matches / new_findings / suppressed / skipped_unchanged。

## 5. 评测

- synthetic-regression-v0.6：24 例，用于版本回归。
- curated-adversarial-v0.6：70 例，包含正例、near miss、placeholder、无认证 DB URI 等，按 risk>=45 作为 actionable 阈值。

这些数据不是自然采样的互联网数据，因此不得作为真实部署准确率声明。

## 6. 隐私与安全

不持久化原始凭据；仅保存 masked value 与 SHA-256 fingerprint。公开 URL 适配器阻止私网、回环、链路本地和保留地址。系统不验证或使用发现的凭据。
