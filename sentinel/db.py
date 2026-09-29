import json
import sqlite3
import threading
from pathlib import Path
from statistics import median
from .timeutil import utcnow_iso

DB = Path('cloudleak.db')
_DB_INIT_LOCK = threading.RLock()


def _cols(con, table):
    return {r[1] for r in con.execute(f'PRAGMA table_info({table})').fetchall()}


def _ensure_column(con, table, name, decl):
    if name not in _cols(con, table):
        try:
            con.execute(f'ALTER TABLE {table} ADD COLUMN {name} {decl}')
        except sqlite3.OperationalError as e:
            # Another startup worker may have added the same migration column.
            if 'duplicate column name' not in str(e).lower():
                raise


def init():
    # Schema initialization is serialized because monitor/job workers may start together.
    # This avoids a journal_mode race on a brand-new SQLite database.
    with _DB_INIT_LOCK:
        con = sqlite3.connect(DB, timeout=10)
        con.execute('PRAGMA busy_timeout=5000')
        try:
            con.execute('PRAGMA journal_mode=WAL')
        except sqlite3.OperationalError:
            # Another connection may already hold a short-lived lock; WAL is an optimization,
            # not a correctness requirement for this request.
            pass
    con.execute('''CREATE TABLE IF NOT EXISTS findings(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fingerprint TEXT NOT NULL,
        source TEXT NOT NULL,
        locator TEXT NOT NULL,
        credential_type TEXT NOT NULL,
        masked_value TEXT,
        confidence REAL,
        severity TEXT,
        reason TEXT,
        observed_at TEXT,
        published_at TEXT,
        UNIQUE(fingerprint, locator, credential_type)
    )''')
    for name, decl in [
        ('channel','TEXT'), ('detection_latency_ms','REAL'), ('risk_score','INTEGER DEFAULT 0'),
        ('evidence_json','TEXT'), ('exposure_state',"TEXT DEFAULT 'current'")
    ]:
        _ensure_column(con, 'findings', name, decl)

    con.execute('''CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT NOT NULL,
        target TEXT NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        artifacts INTEGER DEFAULT 0,
        matches INTEGER DEFAULT 0,
        new_findings INTEGER DEFAULT 0,
        duration_ms REAL DEFAULT 0,
        status TEXT DEFAULT 'running'
    )''')
    _ensure_column(con, 'scans', 'suppressed', 'INTEGER DEFAULT 0')
    _ensure_column(con, 'scans', 'skipped_unchanged', 'INTEGER DEFAULT 0')

    con.execute('''CREATE TABLE IF NOT EXISTS alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id INTEGER,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at TEXT NOT NULL,
        acknowledged INTEGER DEFAULT 0,
        acknowledged_at TEXT,
        FOREIGN KEY(finding_id) REFERENCES findings(id)
    )''')
    con.execute('''CREATE TABLE IF NOT EXISTS monitors(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL,
        target TEXT NOT NULL,
        interval_sec INTEGER NOT NULL DEFAULT 120,
        enabled INTEGER NOT NULL DEFAULT 1,
        cursor TEXT,
        last_run_at TEXT,
        last_status TEXT,
        created_at TEXT NOT NULL,
        UNIQUE(kind,target)
    )''')
    con.execute('''CREATE TABLE IF NOT EXISTS allowlist(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fingerprint TEXT NOT NULL,
        credential_type TEXT,
        reason TEXT,
        created_at TEXT NOT NULL,
        UNIQUE(fingerprint, credential_type)
    )''')
    con.execute('''CREATE TABLE IF NOT EXISTS exposures(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scope TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        credential_type TEXT NOT NULL,
        first_exposed_at TEXT,
        first_locator TEXT,
        first_sha TEXT,
        removed_at TEXT,
        removed_locator TEXT,
        removed_sha TEXT,
        current_present INTEGER NOT NULL DEFAULT 1,
        reexposed_count INTEGER NOT NULL DEFAULT 0,
        last_seen_at TEXT,
        UNIQUE(scope,fingerprint,credential_type)
    )''')
    con.execute('''CREATE TABLE IF NOT EXISTS artifact_cache(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT NOT NULL,
        locator TEXT NOT NULL,
        content_sha256 TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        UNIQUE(source,locator)
    )''')
    con.execute('''CREATE TABLE IF NOT EXISTS jobs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL,
        target TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'queued',
        created_at TEXT NOT NULL,
        started_at TEXT,
        finished_at TEXT,
        processed INTEGER NOT NULL DEFAULT 0,
        matches INTEGER NOT NULL DEFAULT 0,
        new_findings INTEGER NOT NULL DEFAULT 0,
        suppressed INTEGER NOT NULL DEFAULT 0,
        skipped_unchanged INTEGER NOT NULL DEFAULT 0,
        duration_ms REAL NOT NULL DEFAULT 0,
        error TEXT
    )''')
    con.commit()
    return con


def begin_scan(source, target):
    con = init()
    try:
        cur = con.execute('INSERT INTO scans(source,target,started_at) VALUES(?,?,?)', (source, target, utcnow_iso()))
        con.commit()
        return cur.lastrowid
    finally:
        con.close()


def finish_scan(scan_id, artifacts, matches, new_findings, duration_ms, status='ok', suppressed=0, skipped_unchanged=0):
    con = init()
    try:
        con.execute('''UPDATE scans SET finished_at=?, artifacts=?, matches=?, new_findings=?, duration_ms=?, status=?, suppressed=?, skipped_unchanged=? WHERE id=?''',
                    (utcnow_iso(), artifacts, matches, new_findings, duration_ms, status, int(suppressed), int(skipped_unchanged), scan_id))
        con.commit()
    finally:
        con.close()


def save(f):
    con = init()
    try:
        cur = con.execute('''INSERT OR IGNORE INTO findings(
            fingerprint,source,locator,credential_type,masked_value,confidence,severity,reason,observed_at,published_at,
            channel,detection_latency_ms,risk_score,evidence_json,exposure_state
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (
            f.fingerprint, f.source, f.locator, f.credential_type, f.masked_value,
            f.confidence, f.severity, f.reason, f.observed_at, f.published_at,
            f.channel, f.detection_latency_ms, int(f.risk_score or 0),
            json.dumps(f.evidence or [], ensure_ascii=False), f.exposure_state or 'current'
        ))
        con.commit()
        if cur.rowcount <= 0:
            return False, None
        return True, cur.lastrowid
    finally:
        con.close()


def _row_to_finding_dict(row):
    d = dict(row)
    try:
        d['evidence'] = json.loads(d.pop('evidence_json') or '[]')
    except Exception:
        d['evidence'] = []
        d.pop('evidence_json', None)
    return d


def create_alert(finding_id, severity, title, message):
    con = init()
    try:
        cur = con.execute('''INSERT INTO alerts(finding_id,severity,title,message,created_at)
                             VALUES(?,?,?,?,?)''',
                          (finding_id, severity, title, message, utcnow_iso()))
        con.commit()
        return cur.lastrowid
    finally:
        con.close()


def _attach_lifecycle(con, d):
    scope = None
    locator = d.get('locator') or ''
    if locator.startswith('git://') and '@' in locator:
        scope = 'git:' + locator[len('git://'):].split('@', 1)[0]
    if scope:
        row = con.execute("""SELECT scope,first_exposed_at,first_locator,first_sha,removed_at,removed_locator,removed_sha,
                                    current_present,reexposed_count,last_seen_at
                             FROM exposures WHERE scope=? AND fingerprint=? AND credential_type=?
                             ORDER BY id DESC LIMIT 1""", (scope, d.get('fingerprint'), d.get('credential_type'))).fetchone()
    else:
        row = con.execute("""SELECT scope,first_exposed_at,first_locator,first_sha,removed_at,removed_locator,removed_sha,
                                    current_present,reexposed_count,last_seen_at
                             FROM exposures WHERE fingerprint=? AND credential_type=?
                             ORDER BY id DESC LIMIT 1""", (d.get('fingerprint'), d.get('credential_type'))).fetchone()
    if row:
        life = dict(row)
        life['state'] = 'exposed' if life.get('current_present') else 'removed'
        d['lifecycle'] = life
    else:
        d['lifecycle'] = None
    return d


def all_findings(limit=500):
    con = init(); con.row_factory = sqlite3.Row
    try:
        return [_attach_lifecycle(con, _row_to_finding_dict(x)) for x in con.execute(
            'SELECT * FROM findings ORDER BY id DESC LIMIT ?', (int(limit),)
        ).fetchall()]
    finally:
        con.close()


def finding_by_id(finding_id):
    con = init(); con.row_factory = sqlite3.Row
    try:
        row = con.execute('SELECT * FROM findings WHERE id=?', (int(finding_id),)).fetchone()
        return _attach_lifecycle(con, _row_to_finding_dict(row)) if row else None
    finally:
        con.close()


def recent_scans(limit=20):
    con = init(); con.row_factory = sqlite3.Row
    try:
        return [dict(x) for x in con.execute(
            'SELECT * FROM scans ORDER BY id DESC LIMIT ?', (int(limit),)
        ).fetchall()]
    finally:
        con.close()


def alerts(limit=100, unacked_only=False):
    con = init(); con.row_factory = sqlite3.Row
    try:
        where = 'WHERE acknowledged=0' if unacked_only else ''
        q = f'SELECT * FROM alerts {where} ORDER BY id DESC LIMIT ?'
        return [dict(x) for x in con.execute(q, (int(limit),)).fetchall()]
    finally:
        con.close()


def acknowledge_alert(alert_id):
    con = init()
    try:
        cur = con.execute('UPDATE alerts SET acknowledged=1, acknowledged_at=? WHERE id=?', (utcnow_iso(), int(alert_id)))
        con.commit()
        return cur.rowcount > 0
    finally:
        con.close()


def add_allowlist(fingerprint, credential_type=None, reason='manual allowlist'):
    con = init()
    try:
        con.execute('''INSERT INTO allowlist(fingerprint,credential_type,reason,created_at)
                       VALUES(?,?,?,?)
                       ON CONFLICT(fingerprint,credential_type) DO UPDATE SET reason=excluded.reason''',
                    (fingerprint, credential_type, reason, utcnow_iso()))
        con.commit()
        row = con.execute('SELECT id FROM allowlist WHERE fingerprint=? AND credential_type IS ?', (fingerprint, credential_type)).fetchone()
        return row[0] if row else None
    finally:
        con.close()


def allowlist_from_finding(finding_id, reason='manual allowlist'):
    f = finding_by_id(finding_id)
    if not f:
        return None
    return add_allowlist(f['fingerprint'], f['credential_type'], reason)


def is_allowlisted(fingerprint, credential_type):
    con = init()
    try:
        row = con.execute('''SELECT id FROM allowlist WHERE fingerprint=? AND (credential_type=? OR credential_type IS NULL) LIMIT 1''',
                          (fingerprint, credential_type)).fetchone()
        return bool(row)
    finally:
        con.close()


def list_allowlist():
    con = init(); con.row_factory = sqlite3.Row
    try:
        return [dict(x) for x in con.execute('SELECT * FROM allowlist ORDER BY id DESC').fetchall()]
    finally:
        con.close()



def record_lifecycle(scope, f, action='added', metadata=None):
    """Record Git secret exposure/removal without persisting raw credential material."""
    metadata = metadata or {}
    scope = str(scope or 'unknown')
    sha = metadata.get('sha')
    event_at = f.published_at or f.observed_at
    con = init(); con.row_factory = sqlite3.Row
    try:
        row = con.execute("SELECT * FROM exposures WHERE scope=? AND fingerprint=? AND credential_type=?",
                          (scope, f.fingerprint, f.credential_type)).fetchone()
        if action == 'removed':
            if row:
                con.execute("""UPDATE exposures SET removed_at=?,removed_locator=?,removed_sha=?,current_present=0,last_seen_at=?
                               WHERE scope=? AND fingerprint=? AND credential_type=?""",
                            (event_at, f.locator, sha, f.observed_at, scope, f.fingerprint, f.credential_type))
            else:
                con.execute("""INSERT INTO exposures(scope,fingerprint,credential_type,removed_at,removed_locator,removed_sha,
                                                     current_present,last_seen_at)
                               VALUES(?,?,?,?,?,?,0,?)""",
                            (scope, f.fingerprint, f.credential_type, event_at, f.locator, sha, f.observed_at))
        else:
            if row:
                was_removed = int(row['current_present']) == 0
                con.execute("""UPDATE exposures SET current_present=1,removed_at=NULL,removed_locator=NULL,removed_sha=NULL,
                                      last_seen_at=?, reexposed_count=reexposed_count+?
                               WHERE scope=? AND fingerprint=? AND credential_type=?""",
                            (f.observed_at, 1 if was_removed else 0, scope, f.fingerprint, f.credential_type))
            else:
                con.execute("""INSERT INTO exposures(scope,fingerprint,credential_type,first_exposed_at,first_locator,first_sha,
                                                     current_present,last_seen_at)
                               VALUES(?,?,?,?,?,?,1,?)""",
                            (scope, f.fingerprint, f.credential_type, event_at, f.locator, sha, f.observed_at))
        con.commit()
    finally:
        con.close()


def list_exposures(limit=200):
    con = init(); con.row_factory = sqlite3.Row
    try:
        rows = [dict(x) for x in con.execute("SELECT * FROM exposures ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()]
        for x in rows:
            x['state'] = 'exposed' if x.get('current_present') else 'removed'
        return rows
    finally:
        con.close()


def delete_allowlist(item_id):
    con = init()
    try:
        cur = con.execute('DELETE FROM allowlist WHERE id=?', (int(item_id),))
        con.commit()
        return cur.rowcount > 0
    finally:
        con.close()


def upsert_monitor(kind, target, interval_sec=120, enabled=True):
    con = init(); now = utcnow_iso()
    try:
        con.execute('''INSERT INTO monitors(kind,target,interval_sec,enabled,created_at)
                       VALUES(?,?,?,?,?)
                       ON CONFLICT(kind,target) DO UPDATE SET interval_sec=excluded.interval_sec, enabled=excluded.enabled''',
                    (kind, target, int(interval_sec), 1 if enabled else 0, now))
        con.commit()
        row = con.execute('SELECT id FROM monitors WHERE kind=? AND target=?', (kind, target)).fetchone()
        return row[0]
    finally:
        con.close()


def list_monitors():
    con = init(); con.row_factory = sqlite3.Row
    try:
        return [dict(x) for x in con.execute('SELECT * FROM monitors ORDER BY id DESC').fetchall()]
    finally:
        con.close()


def due_monitors(now_epoch):
    con = init(); con.row_factory = sqlite3.Row
    try:
        rows = [dict(x) for x in con.execute('SELECT * FROM monitors WHERE enabled=1').fetchall()]
    finally:
        con.close()
    import datetime
    out = []
    for r in rows:
        if not r['last_run_at']:
            out.append(r); continue
        try:
            last = datetime.datetime.fromisoformat(r['last_run_at'].replace('Z','+00:00')).timestamp()
        except Exception:
            out.append(r); continue
        if now_epoch - last >= r['interval_sec']:
            out.append(r)
    return out


def update_monitor_state(monitor_id, cursor=None, status='ok'):
    con = init()
    try:
        if cursor is None:
            con.execute('UPDATE monitors SET last_run_at=?, last_status=? WHERE id=?', (utcnow_iso(), status, int(monitor_id)))
        else:
            con.execute('UPDATE monitors SET last_run_at=?, last_status=?, cursor=? WHERE id=?', (utcnow_iso(), status, cursor, int(monitor_id)))
        con.commit()
    finally:
        con.close()


def delete_monitor(monitor_id):
    con = init()
    try:
        cur = con.execute('DELETE FROM monitors WHERE id=?', (int(monitor_id),))
        con.commit()
        return cur.rowcount > 0
    finally:
        con.close()


def metrics():
    con = init(); con.row_factory = sqlite3.Row
    try:
        total = con.execute('SELECT COUNT(*) n FROM findings').fetchone()['n']
        critical = con.execute("SELECT COUNT(*) n FROM findings WHERE severity='critical'").fetchone()['n']
        history = con.execute("SELECT COUNT(*) n FROM findings WHERE exposure_state='history'").fetchone()['n']
        lifecycle_total = con.execute('SELECT COUNT(*) n FROM exposures').fetchone()['n']
        lifecycle_removed = con.execute('SELECT COUNT(*) n FROM exposures WHERE current_present=0').fetchone()['n']
        today = con.execute("SELECT COUNT(*) n FROM findings WHERE date(observed_at)=date('now')").fetchone()['n']
        unacked = con.execute('SELECT COUNT(*) n FROM alerts WHERE acknowledged=0').fetchone()['n']
        allowlisted = con.execute('SELECT COUNT(*) n FROM allowlist').fetchone()['n']
        suppressed = con.execute('SELECT COALESCE(SUM(suppressed),0) n FROM scans').fetchone()['n']
        avg_ms = con.execute("SELECT AVG(duration_ms) v FROM scans WHERE status='ok'").fetchone()['v'] or 0
        avg_risk = con.execute('SELECT AVG(risk_score) v FROM findings').fetchone()['v'] or 0
        total_artifacts = con.execute("SELECT COALESCE(SUM(artifacts),0) n FROM scans WHERE status='ok'").fetchone()['n']
        total_duration_ms = con.execute("SELECT COALESCE(SUM(duration_ms),0) n FROM scans WHERE status='ok'").fetchone()['n']
        throughput = (total_artifacts / (total_duration_ms/1000.0)) if total_duration_ms else 0
        queued_jobs = con.execute("SELECT COUNT(*) n FROM jobs WHERE status='queued'").fetchone()['n']
        running_jobs = con.execute("SELECT COUNT(*) n FROM jobs WHERE status='running'").fetchone()['n']
        latencies = [r['detection_latency_ms'] for r in con.execute(
            'SELECT detection_latency_ms FROM findings WHERE detection_latency_ms IS NOT NULL AND detection_latency_ms >= 0 ORDER BY detection_latency_ms'
        ).fetchall()]
        p50 = median(latencies) if latencies else None
        p95 = None
        if latencies:
            idx = min(len(latencies)-1, max(0, int(round(0.95 * (len(latencies)-1)))))
            p95 = latencies[idx]
        by_type = [dict(x) for x in con.execute('''SELECT credential_type name, COUNT(*) value
                                                   FROM findings GROUP BY credential_type
                                                   ORDER BY value DESC LIMIT 10''').fetchall()]
        by_source = [dict(x) for x in con.execute('''SELECT COALESCE(channel,source) name, COUNT(*) value
                                                     FROM findings GROUP BY COALESCE(channel,source)
                                                     ORDER BY value DESC LIMIT 10''').fetchall()]
        latest_timeline_row = con.execute('''SELECT id,credential_type,severity,risk_score,published_at,observed_at,detection_latency_ms,locator
                                             FROM findings WHERE published_at IS NOT NULL
                                             ORDER BY id DESC LIMIT 1''').fetchone()
        return {
            'total_findings': total,
            'critical_findings': critical,
            'history_findings': history,
            'lifecycle_total': lifecycle_total,
            'lifecycle_removed': lifecycle_removed,
            'today_findings': today,
            'unacked_alerts': unacked,
            'allowlist_count': allowlisted,
            'suppressed_total': suppressed,
            'avg_scan_ms': round(avg_ms, 1),
            'avg_risk_score': round(avg_risk, 1),
            'total_artifacts': int(total_artifacts or 0),
            'throughput_artifacts_s': round(throughput, 1),
            'queued_jobs': int(queued_jobs or 0),
            'running_jobs': int(running_jobs or 0),
            'latency_samples': len(latencies),
            'p50_detection_latency_ms': round(p50, 1) if p50 is not None else None,
            'p95_detection_latency_ms': round(p95, 1) if p95 is not None else None,
            'by_type': by_type,
            'by_source': by_source,
            'latest_timeline': dict(latest_timeline_row) if latest_timeline_row else None,
        }
    finally:
        con.close()


def query_findings(limit=200, severity=None, channel=None, q=None, min_risk=0, exposure_state=None):
    """Filtered finding search for the SOC view. All parameters are bound, never interpolated into SQL."""
    con = init(); con.row_factory = sqlite3.Row
    try:
        where = []
        args = []
        if severity:
            where.append('severity=?'); args.append(str(severity).lower())
        if channel:
            where.append('COALESCE(channel,source)=?'); args.append(str(channel))
        if exposure_state:
            where.append('exposure_state=?'); args.append(str(exposure_state))
        if int(min_risk or 0) > 0:
            where.append('risk_score>=?'); args.append(int(min_risk))
        if q:
            where.append('(credential_type LIKE ? OR locator LIKE ? OR masked_value LIKE ?)')
            like = '%' + str(q)[:120] + '%'
            args += [like, like, like]
        clause = (' WHERE ' + ' AND '.join(where)) if where else ''
        args.append(int(limit))
        rows = con.execute('SELECT * FROM findings' + clause + ' ORDER BY id DESC LIMIT ?', args).fetchall()
        return [_attach_lifecycle(con, _row_to_finding_dict(x)) for x in rows]
    finally:
        con.close()


def artifact_changed(source, locator, content_sha256):
    """Return True when content is new/changed, and atomically update the cache."""
    con = init()
    try:
        row = con.execute('SELECT content_sha256 FROM artifact_cache WHERE source=? AND locator=?',
                          (str(source), str(locator))).fetchone()
        changed = not row or row[0] != str(content_sha256)
        con.execute('''INSERT INTO artifact_cache(source,locator,content_sha256,last_seen_at)
                       VALUES(?,?,?,?)
                       ON CONFLICT(source,locator) DO UPDATE SET content_sha256=excluded.content_sha256,
                                                               last_seen_at=excluded.last_seen_at''',
                    (str(source), str(locator), str(content_sha256), utcnow_iso()))
        con.commit()
        return changed
    finally:
        con.close()


def create_job(kind, target, payload):
    con = init()
    try:
        cur = con.execute('''INSERT INTO jobs(kind,target,payload_json,status,created_at)
                             VALUES(?,?,?,'queued',?)''',
                          (str(kind), str(target), json.dumps(payload, ensure_ascii=False), utcnow_iso()))
        con.commit()
        return cur.lastrowid
    finally:
        con.close()


def claim_next_job():
    """Claim one queued job. BEGIN IMMEDIATE keeps concurrent workers from double-claiming."""
    con = init(); con.row_factory = sqlite3.Row
    try:
        con.execute('BEGIN IMMEDIATE')
        row = con.execute("SELECT * FROM jobs WHERE status='queued' ORDER BY id LIMIT 1").fetchone()
        if not row:
            con.commit(); return None
        cur = con.execute("UPDATE jobs SET status='running', started_at=? WHERE id=? AND status='queued'",
                          (utcnow_iso(), row['id']))
        con.commit()
        if cur.rowcount != 1:
            return None
        d = dict(row); d['status'] = 'running'; d['started_at'] = utcnow_iso()
        try: d['payload'] = json.loads(d.pop('payload_json'))
        except Exception: d['payload'] = {}
        return d
    finally:
        con.close()


def update_job_progress(job_id, processed=None, matches=None, new_findings=None, suppressed=None, skipped_unchanged=None):
    fields=[]; args=[]
    for name, val in [('processed',processed),('matches',matches),('new_findings',new_findings),
                      ('suppressed',suppressed),('skipped_unchanged',skipped_unchanged)]:
        if val is not None:
            fields.append(f'{name}=?'); args.append(int(val))
    if not fields: return
    args.append(int(job_id))
    con=init()
    try:
        con.execute('UPDATE jobs SET ' + ','.join(fields) + ' WHERE id=?', args); con.commit()
    finally: con.close()


def finish_job(job_id, *, status='done', processed=0, matches=0, new_findings=0, suppressed=0,
               skipped_unchanged=0, duration_ms=0, error=None):
    con=init()
    try:
        con.execute('''UPDATE jobs SET status=?,finished_at=?,processed=?,matches=?,new_findings=?,suppressed=?,
                       skipped_unchanged=?,duration_ms=?,error=? WHERE id=?''',
                    (status,utcnow_iso(),int(processed),int(matches),int(new_findings),int(suppressed),
                     int(skipped_unchanged),float(duration_ms or 0),str(error)[:1000] if error else None,int(job_id)))
        con.commit()
    finally: con.close()


def list_jobs(limit=50, status=None):
    con=init(); con.row_factory=sqlite3.Row
    try:
        if status:
            rows=con.execute('SELECT * FROM jobs WHERE status=? ORDER BY id DESC LIMIT ?', (status,int(limit))).fetchall()
        else:
            rows=con.execute('SELECT * FROM jobs ORDER BY id DESC LIMIT ?', (int(limit),)).fetchall()
        out=[]
        for r in rows:
            d=dict(r)
            try: d['payload']=json.loads(d.pop('payload_json'))
            except Exception: d['payload']={}; d.pop('payload_json',None)
            out.append(d)
        return out
    finally: con.close()


def job_by_id(job_id):
    con=init(); con.row_factory=sqlite3.Row
    try:
        r=con.execute('SELECT * FROM jobs WHERE id=?',(int(job_id),)).fetchone()
        if not r:return None
        d=dict(r)
        try:d['payload']=json.loads(d.pop('payload_json'))
        except Exception:d['payload']={};d.pop('payload_json',None)
        return d
    finally:con.close()


def reset_interrupted_jobs():
    """On process restart, return unfinished jobs to the queue rather than losing them."""
    con=init()
    try:
        con.execute("UPDATE jobs SET status='queued',started_at=NULL,error='resumed after service restart' WHERE status='running'")
        con.commit()
    finally: con.close()


def recent_scan_by_source(source_names):
    con=init(); con.row_factory=sqlite3.Row
    try:
        out={}
        for name in source_names:
            r=con.execute('SELECT * FROM scans WHERE source=? ORDER BY id DESC LIMIT 1',(name,)).fetchone()
            if r: out[name]=dict(r)
        return out
    finally: con.close()


def load_artifact_cache():
    con=init(); con.row_factory=sqlite3.Row
    try:
        return {(r['source'],r['locator']):r['content_sha256'] for r in con.execute(
            'SELECT source,locator,content_sha256 FROM artifact_cache'
        ).fetchall()}
    finally: con.close()


def upsert_artifact_cache_many(rows):
    rows=list(rows)
    if not rows:return
    now=utcnow_iso(); con=init()
    try:
        con.executemany('''INSERT INTO artifact_cache(source,locator,content_sha256,last_seen_at)
                           VALUES(?,?,?,?)
                           ON CONFLICT(source,locator) DO UPDATE SET content_sha256=excluded.content_sha256,
                                                                   last_seen_at=excluded.last_seen_at''',
                        [(str(a),str(b),str(c),now) for a,b,c in rows])
        con.commit()
    finally: con.close()
