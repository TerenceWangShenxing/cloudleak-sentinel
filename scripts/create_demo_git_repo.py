#!/usr/bin/env python3
"""Create a local synthetic Git repository for safe history-leak demonstrations.

The repository contains only invented credentials and is intended for CloudLeak Sentinel demos.
"""
from pathlib import Path
import argparse
import shutil
import subprocess
import time


def run(path: Path, *args):
    subprocess.check_call(['git', '-C', str(path), *args], stdout=subprocess.DEVNULL)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('path', nargs='?', default='/tmp/cloudleak-history-demo')
    args = ap.parse_args()
    p = Path(args.path).expanduser().resolve()
    if p.exists():
        shutil.rmtree(p)
    p.mkdir(parents=True)
    run(p, 'init', '-q')
    run(p, 'config', 'user.email', 'demo@cloudleak.invalid')
    run(p, 'config', 'user.name', 'CloudLeak Demo')

    (p / 'config.env').write_text(
        '# SYNTHETIC DEMO ONLY\n'
        'HUAWEI_CLOUD_AK=' + ('AB12' + 'CD34EF56GH78IJ90') + '\n'
        'HUAWEI_CLOUD_SK=' + ('X9q7' + 'Lm4P2vN8rT6sK5w3Z1y8B4c6D0f2') + '\n'
        'password=HistoryDemo_Q9x7L4m2N8p6\n', encoding='utf-8')
    run(p, 'add', 'config.env')
    run(p, 'commit', '-q', '-m', 'demo: accidentally add synthetic credential')
    time.sleep(1)

    (p / 'config.env').write_text(
        '# SYNTHETIC DEMO ONLY\n'
        'HUAWEI_CLOUD_AK=${HUAWEI_CLOUD_AK}\n'
        'HUAWEI_CLOUD_SK=${HUAWEI_CLOUD_SK}\n'
        'password=${APP_PASSWORD}\n', encoding='utf-8')
    run(p, 'add', 'config.env')
    run(p, 'commit', '-q', '-m', 'demo: remove synthetic credential from HEAD')
    print(p)


if __name__ == '__main__':
    main()
