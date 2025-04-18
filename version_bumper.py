#!/usr/bin/env python3
"""
Version Bumper - Generic project versioning tool

Scans source files in a project for semantic version strings and bumps
the major, minor, or patch segment. Updates CHANGELOG.md and optionally commits and tags via Git.

Usage:
  version_bumper.py [options]

Options:
  -p, --project PATH          Root path of the project (default: current directory)
  -t, --type {major,minor,patch}  Segment to bump [patch]
  -f, --find-pattern PATTERN  Regex to find the version string
                              (default: __version__\s*=\s*["'](\d+\.\d+\.\d+)["'])
  -c, --commit                Commit bumps to Git
  -g, --git-tag               Create a Git tag after bump
  -m, --message MSG           Commit/tag message (supports {version})
                              [chore: bump version to {version}]
  --dry-run                   Show changes without writing files
  --exclude DIRS              Comma-separated dirs to skip (default: .git,env,venv,.venv,.env,.idea,.vscode)
"""

import os
import re
import sys
import argparse
import subprocess
import logging
from datetime import datetime

__version__ = "1.0.0"

def setup_logging(verbose: bool) -> None:
    """Configure logging output."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s [%(levelname)s] %(message)s')

def find_files(root: str, exclude_dirs: list[str]) -> list[str]:
    """Yield Python files under root, skipping exclude_dirs."""
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for f in filenames:
            if f.endswith('.py'):
                files.append(os.path.join(dirpath, f))
    return files

def bump_version_in_file(path: str, pattern: str, bump_type: str, dry_run: bool) -> str | None:
    """Read file, bump version per pattern, and write back if changed."""
    with open(path, 'r', encoding='utf-8') as f:
        text = f.read()
    match = re.search(pattern, text)
    if not match:
        return None
    old_ver = match.group(1)
    major, minor, patch = map(int, old_ver.split('.'))
    if bump_type == 'major':
        major += 1
        minor = 0
        patch = 0
    elif bump_type == 'minor':
        minor += 1
        patch = 0
    else:
        patch += 1
    new_ver = f"{major}.{minor}.{patch}"
    new_text = re.sub(pattern, f'__version__ = "{new_ver}"', text)
    if new_text != text:
        logging.info("Bumping %s: %s -> %s", path, old_ver, new_ver)
        if not dry_run:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(new_text)
    return new_ver if new_text != text else None

def update_changelog(project: str, new_version: str, dry_run: bool) -> None:
    """Append new version entry to CHANGELOG.md."""
    changelog_path = os.path.join(project, 'CHANGELOG.md')
    try:
        with open(changelog_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        content = "# Changelog\n\n"
    date = datetime.now().strftime('%Y-%m-%d')
    new_entry = f"## [{new_version}] - {date}\n\n- Updated project to version {new_version}\n\n"
    new_content = new_entry + content
    logging.info("Updating %s with version %s", changelog_path, new_version)
    if not dry_run:
        with open(changelog_path, 'w', encoding='utf-8') as f:
            f.write(new_content)

def git_commit_and_tag(project: str, version: str, message: str, dry_run: bool) -> None:
    """Git add, commit, and tag the new version."""
    cmds = [
        ['git', 'add', '.'],
        ['git', 'commit', '-m', message.format(version=version)]
    ]
    for cmd in cmds:
        logging.debug("Running %s", cmd)
        if not dry_run:
            subprocess.run(cmd, cwd=project, check=True)
    tag_cmd = ['git', 'tag', '-a', f'v{version}', '-m', message.format(version=version)]
    logging.debug("Running %s", tag_cmd)
    if not dry_run:
        subprocess.run(tag_cmd, cwd=project, check=True)

def main() -> None:
    """Parse arguments and bump version."""
    parser = argparse.ArgumentParser(description="Version Bumper - SemVer helper")
    parser.add_argument('-p', '--project', default=os.getcwd(),
                        help='Path to project root')
    parser.add_argument('-t', '--type', choices=['major', 'minor', 'patch'], default='patch',
                        help='Version segment to bump')
    parser.add_argument('-f', '--find-pattern',
                        default=r'__version__\s*=\s*["\'](\d+\.\d+\.\d+)["\']',
                        help='Regex to locate version string')
    parser.add_argument('-c', '--commit', action='store_true', help='Commit bump to Git')
    parser.add_argument('-g', '--git-tag', action='store_true', help='Create Git tag')
    parser.add_argument('-m', '--message', default='chore: bump version to {version}',
                        help='Commit/tag message format')
    parser.add_argument('--dry-run', action='store_true', help='Show changes without writing')
    parser.add_argument('--exclude', default='.git,env,venv,.venv,.env,.idea,.vscode',
                        help='Comma-separated dirs to skip')

    args = parser.parse_args()
    setup_logging(args.message == 'chore: bump version to {version}')

    exclude_dirs = args.exclude.split(',')

    new_version = None
    for file in find_files(args.project, exclude_dirs):
        result = bump_version_in_file(file, args.find_pattern, args.type, args.dry_run)
        if result:
            new_version = result

    if new_version:
        logging.info("New version: %s", new_version)
        update_changelog(args.project, new_version, args.dry_run)
        if args.commit or args.git_tag:
            git_commit_and_tag(args.project, new_version, args.message, args.dry_run)
    else:
        logging.info("No version string found or no change needed.")

if __name__ == '__main__':
    main()