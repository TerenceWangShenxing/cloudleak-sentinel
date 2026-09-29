from dataclasses import dataclass, asdict


@dataclass
class PluginInfo:
    id: str
    name: str
    status: str
    mode: str
    notes: str


PLUGINS = [
    PluginInfo('filesystem', 'Local Files / Git Workspace', 'ready', 'pull', 'Text/config scanning with bounded archive handling'),
    PluginInfo('local-git-history', 'Local Git Lifecycle', 'ready', 'pull', 'Tracks add/remove lifecycle; deletion commits do not create duplicate findings'),
    PluginInfo('public-url', 'Public Text URL', 'ready', 'pull', 'Explicit public HTTP/HTTPS text target only'),
    PluginInfo('wiki', 'Public Wiki / Knowledge Page', 'ready', 'pull', 'One explicit public HTML/text page; visible/code text normalization'),
    PluginInfo('github-repo', 'GitHub Repository', 'ready', 'pull', 'Explicit owner/repo only; optional GITHUB_TOKEN'),
    PluginInfo('github-webhook', 'GitHub Push Webhook', 'ready', 'push', 'Event-driven commit scanning; optional HMAC verification'),
    PluginInfo('github-monitor', 'GitHub Repository Monitor', 'ready', 'poll', 'Repository-scoped polling with cursor'),
    PluginInfo('gitee-repo', 'Gitee Repository', 'beta', 'pull', 'Explicit owner/repo only; optional GITEE_TOKEN'),
    PluginInfo('docker-image', 'Docker / OCI Image TAR', 'ready', 'pull', 'Docker-save manifest + config.Env + nested layer static scan'),
    PluginInfo('apk', 'Android APK', 'ready', 'pull', 'Assets/resources plus bounded strings from DEX/resources; never executes app'),
    PluginInfo('mini-program', 'Mini Program Package', 'beta', 'pull', 'Unpacked project/ZIP/wxapkg bounded static string analysis'),
    PluginInfo('archive-upload', 'Browser Upload', 'ready', 'push', 'Bounded APK/ZIP/TAR/wxapkg upload for local competition demo'),
]


def catalog():
    return [asdict(x) for x in PLUGINS]
