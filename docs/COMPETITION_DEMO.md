# v0.6 现场演示建议

所有演示数据都是脚本生成的合成凭据，不使用真实账号秘密。

## 一键填充 Dashboard

在已激活虚拟环境的终端中：

```bash
bash scripts/demo_all.sh
```

它会演示 5 条路径：本地配置、Git 生命周期、Docker layer、APK、小程序 ZIP。随后刷新 Dashboard。

## 推荐答辩顺序

1. 首页：说明渠道数、检测器数、Critical、P50/P95。
2. Git 生命周期：展示同一 Secret 只有一条风险 Finding，但生命周期有 first exposed 和 removed commit。
3. Docker：说明不是只扫 TAR 表层，而是解析 manifest/config.Env/nested layer。
4. APK/小程序：强调静态字符串与资源解析，不安装、不执行。
5. Allowlist：把一条合成测试 Secret 加入白名单，再扫描展示 suppressed 增长。
6. Benchmark：明确 synthetic-v0.6 只作为回归基线；真实评测仍需额外公开/授权数据集。
7. `/docs`：展示每个 Source Adapter 对应统一 API，说明扩展新渠道不改检测主链路。

## 不应夸大的点

- Mini-program raw wxapkg 当前是 Beta 字符串提取，不等同于完整反编译。
- Gitee 为 Beta，受官方 API/配额影响。
- Synthetic Benchmark 的 100% 只说明当前规则覆盖这组自建回归样例，不能宣称现实环境准确率 100%。
- 当前不会验证、调用、登录或自动轮换任何发现的真实凭据。

## v0.6 新演示：任务队列与增量扫描

先运行 `python3 scripts/create_demo_packages.py /tmp/cloudleak-demo-artifacts`，再把 `/tmp/cloudleak-demo-artifacts/demo-local.env` 连续入队两次。第一次完整检测；第二次应显示相同对象被 `skipped_unchanged` 跳过，从而直观证明增量扫描而不是重复全量计算。

## v0.6 新演示：对抗性评测

```bash
python3 -m sentinel.cli evaluation
```

强调 70 例仍是人工构造数据，目标是覆盖 near-miss 与 placeholder，而非包装成真实互联网准确率。

## v0.6 新演示：规模基准

```bash
python3 scripts/run_scale_benchmark.py --files 1000
```

报告第一次全量扫描吞吐和第二次增量跳过率。正式答辩应在比赛机/指定环境重复运行，并标明硬件、Python 版本和样本量。
