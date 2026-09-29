"""Safe synthetic throughput/incremental benchmark.

Creates temporary text files containing only fake demo values, runs a full incremental-enabled
scan, then immediately repeats it to measure unchanged-artifact skipping. No network access.
"""
import argparse
import sys
import json
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel.engine import run
from sentinel.sources.filesystem import FileSystemSource


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--files',type=int,default=1000)
    ap.add_argument('--secret-every',type=int,default=25)
    args=ap.parse_args()
    n=max(10,min(100000,args.files)); every=max(1,args.secret_every)
    with tempfile.TemporaryDirectory(prefix='cloudleak-scale-') as td:
        root=Path(td)
        for i in range(n):
            if i % every == 0:
                text=f'api_key=ScaleDemoQ7m2X9p4K8v3N6s1{i:06d}\n'
            else:
                text=f'name=service-{i}\nport={8000+i%100}\nfeature_enabled=true\n'
            (root/f'cfg_{i:06d}.env').write_text(text,encoding='utf-8')
        r1=run(FileSystemSource(str(root)),str(root),incremental=True)
        r2_stats={}
        def cb(s): r2_stats.update(s)
        r2=run(FileSystemSource(str(root)),str(root),incremental=True,progress=cb)
        out={
            'files':n,
            'first_scan':{'matches':len(r1[0]),'new_findings':r1[1],'artifacts':r1[2],'duration_ms':r1[3]},
            'second_incremental_scan':{'matches':len(r2[0]),'new_findings':r2[1],'artifacts':r2[2],'duration_ms':r2[3],
                                       'skipped_unchanged':r2_stats.get('skipped_unchanged',0)},
        }
        out['first_throughput_artifacts_s']=round(n/(r1[3]/1000),1) if r1[3] else None
        out['incremental_skip_rate']=round(r2_stats.get('skipped_unchanged',0)/n,4)
        print(json.dumps(out,ensure_ascii=False,indent=2))

if __name__=='__main__': main()
