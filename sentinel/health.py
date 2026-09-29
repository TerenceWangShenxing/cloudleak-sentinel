import os
from .plugins import catalog
from .db import recent_scan_by_source

_SOURCE_MAP = {
    'filesystem': 'FileSystemSource',
    'local-git-history': 'LocalGitHistorySource',
    'public-url': 'PublicURLSource',
    'wiki': 'PublicWikiPageSource',
    'github-repo': 'GitHubRepoSource',
    'github-webhook': 'GitHubCommitSource',
    'github-monitor': 'GitHubCommitSource',
    'gitee-repo': 'GiteeRepoSource',
    'docker-image': 'DockerImageTarSource',
    'apk': 'MobilePackageSource',
    'mini-program': 'MobilePackageSource',
}


def channel_health():
    plugins = catalog()
    scans = recent_scan_by_source(sorted(set(_SOURCE_MAP.values())))
    out = []
    for p in plugins:
        src = _SOURCE_MAP.get(p['id'])
        last = scans.get(src) if src else None
        configured = True
        configuration = 'none required'
        if p['id'] in {'github-repo', 'github-monitor'}:
            configured = bool(os.getenv('GITHUB_TOKEN'))
            configuration = 'token configured' if configured else 'anonymous API mode'
        elif p['id'] == 'github-webhook':
            configured = bool(os.getenv('GITHUB_WEBHOOK_SECRET'))
            configuration = 'HMAC secret configured' if configured else 'HMAC optional / not configured'
        elif p['id'] == 'gitee-repo':
            configured = bool(os.getenv('GITEE_TOKEN'))
            configuration = 'token configured' if configured else 'anonymous/API-limited mode'
        health = 'beta' if p['status'] == 'beta' else 'ready'
        if last and last.get('status') == 'error':
            health = 'degraded'
        out.append({
            **p,
            'health': health,
            'configured': configured,
            'configuration': configuration,
            'last_scan_at': last.get('finished_at') if last else None,
            'last_scan_status': last.get('status') if last else None,
            'last_duration_ms': last.get('duration_ms') if last else None,
        })
    return out
