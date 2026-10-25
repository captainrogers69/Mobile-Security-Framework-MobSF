#!/usr/bin/env python3
"""Regenerate mobsf/StaticAnalyzer/views/flutter/dart_versions.json.

For every stable Dart SDK in the official archive, download it (sha256
verified), compile an AOT snapshot of a hello world program and read the
snapshot hash from its header. Flutter versions come from Flutter's
official releases JSON (dart_sdk_version).

Usage (from the repository root):
    python scripts/update_flutter_dart_versions.py          # new versions
    python scripts/update_flutter_dart_versions.py --all    # rebuild
"""
import argparse
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

import requests

import django

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# The snapshot parser imports MobSF helpers that need Django set up
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mobsf.MobSF.settings')
django.setup()

from mobsf.StaticAnalyzer.views.flutter.snapshot import (  # noqa: E402
    read_snapshot_header,
)

DATA_FILE = ROOT / 'mobsf/StaticAnalyzer/views/flutter/dart_versions.json'
ARCHIVE = 'https://storage.googleapis.com/dart-archive'
LISTING = ('https://storage.googleapis.com/storage/v1/b/dart-archive/o'
           '?prefix=channels/stable/release/&delimiter=/&maxResults=1000')
FLUTTER_RELEASES = ('https://storage.googleapis.com/flutter_infra_release/'
                    'releases/releases_{}.json')
SEMVER = re.compile(r'^\d+\.\d+\.\d+$')
HASH_RE = re.compile(r'^[0-9a-f]{32}$')
TIMEOUT = 60


def vkey(ver):
    return tuple(int(x) for x in ver.split('.'))


def host_sdk():
    """Return (os, arch) names used in Dart SDK archive file names."""
    osname = {'Darwin': 'macos', 'Linux': 'linux',
              'Windows': 'windows'}[platform.system()]
    machine = platform.machine().lower()
    arch = 'arm64' if machine in ('arm64', 'aarch64') else 'x64'
    return osname, arch


def stable_versions(minimum):
    resp = requests.get(LISTING, timeout=TIMEOUT)
    resp.raise_for_status()
    vers = [p.rstrip('/').split('/')[-1]
            for p in resp.json().get('prefixes', [])]
    vers = [v for v in vers if SEMVER.match(v) and vkey(v) >= vkey(minimum)]
    return sorted(vers, key=vkey)


def flutter_by_dart():
    """Map Dart version -> set of stable Flutter versions."""
    res = {}
    for osname in ('macos', 'linux', 'windows'):
        resp = requests.get(FLUTTER_RELEASES.format(osname), timeout=TIMEOUT)
        resp.raise_for_status()
        for rel in resp.json().get('releases', []):
            dart = (rel.get('dart_sdk_version') or '').split(' ')[0]
            flutter = (rel.get('version') or '').lstrip('v')
            if (rel.get('channel') == 'stable' and SEMVER.match(dart)
                    and SEMVER.match(flutter)):
                res.setdefault(dart, set()).add(flutter)
    return res


def download(url, dest):
    with requests.get(url, stream=True, timeout=TIMEOUT) as resp:
        resp.raise_for_status()
        with open(dest, 'wb') as fobj:
            for chunk in resp.iter_content(1024 * 1024):
                fobj.write(chunk)


def safe_extract(zip_path, dest):
    """Extract a ZIP, rejecting unsafe member names, keeping exec bits."""
    dest = Path(dest).resolve()
    with zipfile.ZipFile(zip_path) as zfile:
        for member in zfile.infolist():
            target = (dest / member.filename).resolve()
            if dest not in target.parents and target != dest:
                raise ValueError(f'Unsafe ZIP member: {member.filename!r}')
            zfile.extract(member, dest)
            mode = (member.external_attr >> 16) & 0o777
            if mode & stat.S_IXUSR:
                os.chmod(target, mode)


def snapshot_hash(version, osname, arch, work):
    """Return the snapshot hash of a Dart SDK release, or None."""
    name = f'dartsdk-{osname}-{arch}-release.zip'
    base = f'{ARCHIVE}/channels/stable/release/{version}/sdk/{name}'
    zip_path = work / name
    try:
        download(base, zip_path)
        want = requests.get(
            f'{base}.sha256sum', timeout=TIMEOUT).text.split()[0]
    except (requests.RequestException, IndexError) as exp:
        print(f'{version}: download failed ({exp})')
        return None
    got = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    if want != got:
        print(f'{version}: sha256 mismatch, skipped')
        return None
    safe_extract(zip_path, work)
    exe = 'dart.exe' if osname == 'windows' else 'dart'
    hello = work / 'hello.dart'
    hello.write_text('void main() => print("hi");\n')
    aot = work / 'hello.aot'
    try:
        subprocess.run(
            [str(work / 'dart-sdk' / 'bin' / exe), 'compile',
             'aot-snapshot', '-o', str(aot), str(hello)],
            check=True, capture_output=True, timeout=300)
    except (OSError, subprocess.SubprocessError) as exp:
        print(f'{version}: compile failed ({exp})')
        return None
    header = read_snapshot_header(aot)
    return header['snapshot_hash'] if header else None


def build_table(dart_hashes, flutter_map):
    """Group Dart versions by hash, ordered by first Dart version."""
    table = {}
    for dart in sorted(dart_hashes, key=vkey):
        entry = table.setdefault(
            dart_hashes[dart], {'dart': [], 'flutter': set()})
        entry['dart'].append(dart)
        entry['flutter'] |= flutter_map.get(dart, set())
    return {
        snap: {'dart': e['dart'],
               'flutter': sorted(e['flutter'], key=vkey)}
        for snap, e in table.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--all', action='store_true',
                        help='rebuild every version instead of new ones')
    parser.add_argument('--min', default='2.14.0',
                        help='oldest Dart version (default: 2.14.0)')
    parser.add_argument('--versions', nargs='*',
                        help='only these Dart versions')
    parser.add_argument('--output', default=str(DATA_FILE))
    args = parser.parse_args()

    out = Path(args.output)
    dart_hashes = {}
    if not args.all and out.exists():
        for snap, entry in json.loads(out.read_text()).items():
            for dart in entry['dart']:
                dart_hashes[dart] = snap
    versions = args.versions or stable_versions(args.min)
    osname, arch = host_sdk()
    for version in versions:
        if version in dart_hashes or not SEMVER.match(version):
            continue
        with tempfile.TemporaryDirectory() as tmp:
            snap = snapshot_hash(version, osname, arch, Path(tmp))
        if snap and HASH_RE.match(snap):
            dart_hashes[version] = snap
            print(f'{version}: {snap}')
    table = build_table(dart_hashes, flutter_by_dart())
    out.write_text(json.dumps(table, indent=1) + '\n')
    print(f'Wrote {len(table)} hashes to {out}')


if __name__ == '__main__':
    main()
