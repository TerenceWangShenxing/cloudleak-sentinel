import hashlib
from time import perf_counter
from .detectors import detect
from .db import save, begin_scan, finish_scan, is_allowlisted, record_lifecycle, load_artifact_cache, upsert_artifact_cache_many
from .alerts import emit_alert


def run(source, target='unknown', *, incremental=False, progress=None):
    """Run one source through the detector.

    incremental=True skips artifacts whose normalized content is byte-for-byte unchanged
    since the last incremental run. Lifecycle-only Git artifacts are never skipped because
    add/remove semantics must be preserved.
    """
    scan_id = begin_scan(source.__class__.__name__, str(target))
    started = perf_counter()
    findings = []
    seen = set()
    artifact_count = 0
    new_count = 0
    suppressed = 0
    skipped_unchanged = 0
    cache = load_artifact_cache() if incremental else {}
    cache_updates = []

    def report(status='running'):
        if progress:
            try:
                progress({
                    'scan_id': scan_id, 'status': status, 'processed': artifact_count,
                    'matches': len(findings), 'new_findings': new_count,
                    'suppressed': suppressed, 'skipped_unchanged': skipped_unchanged,
                    'duration_ms': round((perf_counter() - started) * 1000, 1),
                })
            except Exception:
                pass

    try:
        for artifact in source.collect():
            artifact_count += 1
            metadata = artifact.metadata or {}
            git_change = metadata.get('git_change')
            scope = metadata.get('scope')

            if incremental and git_change not in {'added', 'removed'} and not metadata.get('lifecycle_only'):
                digest = hashlib.sha256(artifact.content.encode('utf-8', errors='ignore')).hexdigest()
                key_cache = (artifact.source, artifact.locator)
                unchanged = cache.get(key_cache) == digest
                cache[key_cache] = digest
                cache_updates.append((artifact.source, artifact.locator, digest))
                if unchanged:
                    skipped_unchanged += 1
                    if artifact_count % 20 == 0:
                        report()
                    continue

            detected = detect(artifact)
            if git_change == 'removed' or metadata.get('lifecycle_only'):
                for f in detected:
                    record_lifecycle(scope, f, 'removed', metadata)
                if artifact_count % 20 == 0:
                    report()
                continue

            for f in detected:
                if git_change == 'added':
                    record_lifecycle(scope, f, 'added', metadata)
                key = (f.fingerprint, f.locator, f.credential_type)
                if key in seen:
                    continue
                seen.add(key)
                if is_allowlisted(f.fingerprint, f.credential_type):
                    suppressed += 1
                    continue
                is_new, finding_id = save(f)
                if is_new:
                    new_count += 1
                    emit_alert(finding_id, f)
                findings.append(f)
            if artifact_count % 20 == 0:
                report()

        if cache_updates:
            upsert_artifact_cache_many(cache_updates)
        elapsed_ms = (perf_counter() - started) * 1000
        finish_scan(scan_id, artifact_count, len(findings), new_count, elapsed_ms, 'ok',
                    suppressed=suppressed, skipped_unchanged=skipped_unchanged)
        report('done')
        return findings, new_count, artifact_count, round(elapsed_ms, 1), suppressed
    except Exception:
        if cache_updates:
            try: upsert_artifact_cache_many(cache_updates)
            except Exception: pass
        elapsed_ms = (perf_counter() - started) * 1000
        finish_scan(scan_id, artifact_count, len(findings), new_count, elapsed_ms, 'error',
                    suppressed=suppressed, skipped_unchanged=skipped_unchanged)
        report('error')
        raise
