import json, statistics, time, random
from pathlib import Path
from datetime import datetime, timezone
from .benchmark import run_benchmark, run_evaluation
from .detectors import detect
from .models import Artifact
from .timeutil import utcnow_iso

REPORT = Path('reports/final_experiments.json')

def _artifact(i, positive=True):
    if positive:
        content=f'api_key=ScaleKey_{i:06d}_Q7m2X9p4K8v3Z6'
    else:
        content=f'build_id={i:06d}\nowner=team-{i%17}\nfeature=true'
    return Artifact('ScaleExperiment',f'memory://case/{i}',content,utcnow_iso(),channel='experiment')

def _pct(values,p):
    if not values:return 0.0
    v=sorted(values); idx=min(len(v)-1,max(0,round((len(v)-1)*p)))
    return v[idx]

def run_final_experiments(sizes=(100,1000,10000), save=True):
    random.seed(20260929)
    scale=[]
    for n in sizes:
        t0=time.perf_counter(); matches=0
        for i in range(n):
            matches += len(detect(_artifact(i, positive=(i%4==0))))
        sec=time.perf_counter()-t0
        scale.append({'artifacts':n,'seconds':round(sec,4),'artifacts_per_s':round(n/sec,1) if sec else 0,'matches':matches})

    # Local processing latency, deliberately excludes Internet/API transport latency.
    lat=[]
    for i in range(1000):
        a=_artifact(200000+i, positive=True)
        t0=time.perf_counter(); detect(a); lat.append((time.perf_counter()-t0)*1000)

    # Deterministic incremental-content experiment: first pass hashes all, second pass compares unchanged hashes.
    import hashlib
    cache={}; payloads=[_artifact(300000+i,positive=(i%5==0)) for i in range(10000)]
    t0=time.perf_counter(); changed1=0
    for a in payloads:
        h=hashlib.sha256(a.content.encode()).hexdigest(); key=(a.source,a.locator)
        if cache.get(key)!=h: changed1+=1
        cache[key]=h
    first=time.perf_counter()-t0
    t0=time.perf_counter(); changed2=0
    for a in payloads:
        h=hashlib.sha256(a.content.encode()).hexdigest(); key=(a.source,a.locator)
        if cache.get(key)!=h: changed2+=1
        cache[key]=h
    second=time.perf_counter()-t0

    bm={k:v for k,v in run_benchmark().items() if k!='details'}
    ev={k:v for k,v in run_evaluation().items() if k!='details'}
    report={
      'generated_at':utcnow_iso(),'version':'1.0.0',
      'regression':bm,'curated_adversarial':ev,
      'scale':scale,
      'local_pipeline_latency_ms':{'n':len(lat),'p50':round(statistics.median(lat),4),'p95':round(_pct(lat,.95),4),'max':round(max(lat),4)},
      'incremental_10k':{'artifacts':10000,'first_pass_changed':changed1,'second_pass_changed':changed2,
                         'first_pass_ms':round(first*1000,2),'second_pass_ms':round(second*1000,2),
                         'unchanged_skip_ratio_second':round((10000-changed2)/10000,4)},
      'notes':[
        'Regression and curated-adversarial datasets are synthetic/curated; they are not Internet-wide accuracy claims.',
        'Local pipeline latency measures in-process detector execution only and excludes external network/API delivery latency.',
        'Scale results are machine-dependent and must be rerun on the competition machine for formal reporting.'
      ]
    }
    if save:
        REPORT.parent.mkdir(parents=True,exist_ok=True); REPORT.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    return report

def load_or_run():
    if REPORT.exists():
        try:return json.loads(REPORT.read_text(encoding='utf-8'))
        except Exception:pass
    return run_final_experiments(sizes=(100,1000),save=True)
