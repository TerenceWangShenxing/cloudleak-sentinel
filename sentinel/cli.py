import argparse, json
from .benchmark import run_benchmark, run_evaluation
from .report import export_report
from .engine import run
from .sources.filesystem import FileSystemSource
from .sources.url import PublicURLSource
from .sources.wiki import PublicWikiPageSource
from .sources.github import GitHubRepoSource
from .sources.gitee import GiteeRepoSource
from .sources.git_history import LocalGitHistorySource
from .sources.docker_image import DockerImageTarSource
from .sources.mobile import MobilePackageSource


def _print(result):
    findings, new_count, artifacts, duration_ms, suppressed = result
    print(json.dumps({
        'matches': len(findings), 'new_findings': new_count, 'suppressed': suppressed,
        'artifacts': artifacts, 'duration_ms': duration_ms,
        'findings': [f.to_dict() for f in findings],
    }, ensure_ascii=False, indent=2))


def main():
    p = argparse.ArgumentParser(prog='cloudleak')
    sub = p.add_subparsers(dest='cmd', required=True)
    scan = sub.add_parser('scan'); scan.add_argument('path')
    hist = sub.add_parser('scan-git-history'); hist.add_argument('path'); hist.add_argument('--max-commits', type=int, default=100)
    dock = sub.add_parser('scan-docker'); dock.add_argument('path')
    mob = sub.add_parser('scan-mobile'); mob.add_argument('path')
    url = sub.add_parser('scan-url'); url.add_argument('url')
    wiki = sub.add_parser('scan-wiki'); wiki.add_argument('url')
    gh = sub.add_parser('scan-github'); gh.add_argument('repo'); gh.add_argument('--ref'); gh.add_argument('--max-files', type=int, default=200)
    ge = sub.add_parser('scan-gitee'); ge.add_argument('repo'); ge.add_argument('--ref'); ge.add_argument('--max-files', type=int, default=200)
    sub.add_parser('benchmark')
    sub.add_parser('evaluation')
    rep = sub.add_parser('export-report'); rep.add_argument('--out-dir', default='reports')
    args = p.parse_args()

    if args.cmd == 'scan': _print(run(FileSystemSource(args.path), args.path))
    elif args.cmd == 'scan-git-history':
        src = LocalGitHistorySource(args.path, args.max_commits); _print(run(src, f'{src.path} [lifecycle]'))
    elif args.cmd == 'scan-docker': _print(run(DockerImageTarSource(args.path), args.path))
    elif args.cmd == 'scan-mobile': _print(run(MobilePackageSource(args.path), args.path))
    elif args.cmd == 'scan-url': _print(run(PublicURLSource(args.url), args.url))
    elif args.cmd == 'scan-wiki': _print(run(PublicWikiPageSource(args.url), args.url))
    elif args.cmd == 'scan-github': _print(run(GitHubRepoSource(args.repo, args.ref, args.max_files), args.repo))
    elif args.cmd == 'scan-gitee': _print(run(GiteeRepoSource(args.repo, args.ref, args.max_files), args.repo))
    elif args.cmd == 'benchmark': print(json.dumps(run_benchmark(), ensure_ascii=False, indent=2))
    elif args.cmd == 'evaluation': print(json.dumps(run_evaluation(), ensure_ascii=False, indent=2))
    elif args.cmd == 'export-report':
        a,b = export_report(args.out_dir); print(json.dumps({'json':str(a),'markdown':str(b)}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
