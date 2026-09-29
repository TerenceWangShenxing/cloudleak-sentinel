import os
from pathlib import Path


def test_curated_evaluation_is_labeled_and_strong():
    from sentinel.benchmark import run_evaluation
    run_evaluation.cache_clear()
    r = run_evaluation()
    assert r['dataset'] == 'curated-adversarial-v0.6'
    assert r['cases'] >= 60
    assert r['f1'] >= 0.90
    assert 'real' in r['note'].lower() or 'claim' in r['note'].lower()


def test_filtered_findings_and_incremental_cache(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from sentinel.db import query_findings
    from sentinel.engine import run
    from sentinel.sources.filesystem import FileSystemSource
    p = tmp_path / 'config.env'
    p.write_text('api_key=Q7m2X9p4K8v3N6s1D5f0\n', encoding='utf-8')
    r1 = run(FileSystemSource(str(p)), str(p), incremental=True)
    assert r1[2] == 1 and len(r1[0]) >= 1
    r2 = run(FileSystemSource(str(p)), str(p), incremental=True)
    assert r2[2] == 1 and len(r2[0]) == 0
    rows = query_findings(20, min_risk=45, q='Generic')
    assert rows


def test_job_queue_db_lifecycle(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from sentinel.db import create_job, claim_next_job, finish_job, job_by_id
    jid = create_job('local', '/tmp/demo', {})
    job = claim_next_job()
    assert job['id'] == jid and job['status'] == 'running'
    finish_job(jid, status='done', processed=3, matches=2, new_findings=1, skipped_unchanged=1)
    got = job_by_id(jid)
    assert got['status'] == 'done' and got['skipped_unchanged'] == 1


def test_competition_report_export(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from sentinel.report import export_report
    a,b = export_report(tmp_path/'reports')
    assert a.exists() and b.exists()
    assert 'curated-adversarial-v0.6' in a.read_text()
