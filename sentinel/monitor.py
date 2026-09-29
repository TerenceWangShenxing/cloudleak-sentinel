import os
import threading
import time
from typing import Optional
from .db import due_monitors, update_monitor_state
from .engine import run
from .sources.github import latest_commit, GitHubCommitSource

_stop = threading.Event()
_thread: Optional[threading.Thread] = None


def _run_github_monitor(m):
    latest = latest_commit(m['target'])
    if not latest:
        update_monitor_state(m['id'], status='empty')
        return
    sha = latest.get('sha')
    if not sha:
        update_monitor_state(m['id'], status='invalid')
        return
    if m.get('cursor') == sha:
        update_monitor_state(m['id'], status='no-change')
        return
    run(GitHubCommitSource(m['target'], sha), f"{m['target']}@{sha}")
    update_monitor_state(m['id'], cursor=sha, status='ok')


def tick():
    now = time.time()
    for m in due_monitors(now):
        try:
            if m['kind'] == 'github-repo':
                _run_github_monitor(m)
            else:
                update_monitor_state(m['id'], status='unsupported-kind')
        except Exception as e:
            update_monitor_state(m['id'], status=f'error:{type(e).__name__}')


def _loop():
    while not _stop.is_set():
        tick()
        _stop.wait(5)


def start():
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, name='cloudleak-monitor', daemon=True)
    _thread.start()


def stop():
    _stop.set()
