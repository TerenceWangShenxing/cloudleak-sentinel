from sentinel.experiments import run_final_experiments
from sentinel.demo import inject

def test_final_experiments_small(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    r=run_final_experiments(sizes=(10,30),save=False)
    assert len(r['scale'])==2
    assert r['incremental_10k']['second_pass_changed']==0
    assert r['local_pipeline_latency_ms']['n']==1000

def test_demo_inject(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    found,new,artifacts,ms,suppressed=inject('cloud-pair')
    assert artifacts==1 and new>=1
    assert any('Huawei Cloud AK/SK Pair'==x.credential_type for x in found)
