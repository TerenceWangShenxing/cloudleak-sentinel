import json
from pathlib import Path
from .benchmark import run_benchmark, run_evaluation
from .db import metrics, recent_scans
from .detectors import rule_catalog
from .health import channel_health
from .plugins import catalog
from .timeutil import utcnow_iso


def competition_report():
    m = metrics()
    return {
        'generated_at': utcnow_iso(),
        'version': '1.0.0',
        'project': 'CloudLeak Sentinel',
        'positioning': '多源云凭据暴露持续监测与分钟级响应平台',
        'scope': 'defensive explicit-target / authorized-feed credential exposure monitoring',
        'summary': {
            'implemented_plugins': len(catalog()),
            'credential_detectors': len(rule_catalog()),
            'total_findings': m['total_findings'],
            'critical_findings': m['critical_findings'],
            'latency_samples': m['latency_samples'],
            'p50_detection_latency_ms': m['p50_detection_latency_ms'],
            'p95_detection_latency_ms': m['p95_detection_latency_ms'],
            'throughput_artifacts_s': m.get('throughput_artifacts_s', 0),
        },
        'regression_benchmark': {k:v for k,v in run_benchmark().items() if k != 'details'},
        'curated_evaluation': {k:v for k,v in run_evaluation().items() if k != 'details'},
        'channels': channel_health(),
        'recent_scans': recent_scans(30),
        'limitations': [
            'Synthetic/curated evaluation results are not claims of Internet-wide production accuracy.',
            'Only explicit targets or authorized feeds are supported; the tool does not search arbitrary accounts or validate credentials.',
            'External platform rate limits and terms of service apply.',
            'Detected credential material is masked and fingerprinted before persistence.',
        ],
    }


def export_report(out_dir='reports'):
    out = Path(out_dir); out.mkdir(parents=True, exist_ok=True)
    data = competition_report()
    (out/'competition_report.json').write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
    s=data['summary']; ev=data['curated_evaluation']; bm=data['regression_benchmark']
    lines=[
        '# CloudLeak Sentinel v1.0 终极版实验摘要','',
        f"生成时间：{data['generated_at']}",'',
        '## 核心工程指标','',
        f"- 已实现渠道/解析插件：{s['implemented_plugins']}",
        f"- 凭据检测器：{s['credential_detectors']}",
        f"- 去重发现：{s['total_findings']}",
        f"- Critical：{s['critical_findings']}",
        f"- 时延样本：n={s['latency_samples']}",
        f"- P50 / P95：{s['p50_detection_latency_ms']} / {s['p95_detection_latency_ms']} ms",
        f"- 历史扫描吞吐：{s['throughput_artifacts_s']} artifacts/s",'',
        '## 检测评测','',
        f"- Regression：n={bm['cases']}，Precision={bm['precision']:.3f}，Recall={bm['recall']:.3f}，F1={bm['f1']:.3f}",
        f"- Curated adversarial：n={ev['cases']}，Precision={ev['precision']:.3f}，Recall={ev['recall']:.3f}，F1={ev['f1']:.3f}，actionable threshold={ev['min_risk']}",
        '', '> 注意：两套评测均为合成/人工构造数据，只用于回归与对抗性功能评估，不代表真实互联网准确率。','',
        '## 安全边界','',
    ]
    lines += [f'- {x}' for x in data['limitations']]
    (out/'competition_report.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    return out/'competition_report.json', out/'competition_report.md'
