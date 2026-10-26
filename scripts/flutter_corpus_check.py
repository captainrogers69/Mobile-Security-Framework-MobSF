#!/usr/bin/env python3
"""Regression check of the Flutter analysis on a corpus of real apps.

Runs the Flutter analysis (the code behind `manage.py flutter_scan`) on every
APK/AAB/XAPK/IPA/ZIP in a corpus folder and compares the stable parts of each
result with scripts/flutter_corpus/expected/<file name>.json.

Usage (from the repository root):
    python scripts/flutter_corpus_check.py CORPUS_DIR            # compare
    python scripts/flutter_corpus_check.py CORPUS_DIR --update   # record

Exit code 1 when a result differs from its expected file or one is missing.
The corpus apps are not in the repository; see scripts/flutter_corpus/README.md.
"""
import argparse
import json
import os
import sys
from pathlib import Path

import django

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mobsf.MobSF.settings')
django.setup()

from mobsf.StaticAnalyzer.views.flutter.cli import scan_path  # noqa: E402

EXPECTED_DIR = ROOT / 'scripts' / 'flutter_corpus' / 'expected'
APP_SUFFIXES = ('.apk', '.aab', '.xapk', '.apks', '.ipa', '.zip')


def summary(result):
    """Stable facts of a Flutter result, for comparison."""
    if not result.get('is_flutter'):
        return {'is_flutter': False}
    return {
        'is_flutter': True,
        'platform': result.get('platform'),
        'build_mode': result.get('build_mode'),
        'abis': result.get('abis'),
        'flutter': result.get('flutter'),
        'dart': result.get('dart'),
        'obfuscated': result.get('obfuscated'),
        'split_debug_info': result.get('split_debug_info'),
        'packages': result.get('packages'),
        'plugins': sorted(p['name'] for p in result.get('plugins') or []),
        'deep_linking': result.get('deep_linking'),
        'js_channels': result.get('js_channels'),
        'assets': result.get('assets'),
        'asset_secret_files': sorted(
            s['file'] for s in result.get('asset_secrets') or []),
        'findings': sorted(
            f'{f["severity"]}:{f["id"]}' for f in result.get('findings') or []),
    }


def diff(expected, actual):
    """Return human readable differences between two summaries."""
    lines = []
    for key in sorted(set(expected) | set(actual)):
        if expected.get(key) != actual.get(key):
            lines.append(f'    {key}: expected {expected.get(key)!r}, '
                         f'got {actual.get(key)!r}')
    return lines


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('corpus', help='folder with the corpus apps')
    parser.add_argument('--update', action='store_true',
                        help='write the expected files instead of comparing')
    args = parser.parse_args()

    apps = sorted(p for p in Path(args.corpus).iterdir()
                  if p.suffix.lower() in APP_SUFFIXES)
    if not apps:
        sys.exit(f'No apps found in {args.corpus}')
    EXPECTED_DIR.mkdir(parents=True, exist_ok=True)
    failures = 0
    for app in apps:
        actual = summary(scan_path(app))
        expected_file = EXPECTED_DIR / f'{app.name}.json'
        if args.update:
            expected_file.write_text(json.dumps(actual, indent=1) + '\n')
            print(f'recorded {app.name}')
            continue
        if not expected_file.exists():
            failures += 1
            print(f'MISSING  {app.name}: no expected file')
            continue
        lines = diff(json.loads(expected_file.read_text()), actual)
        if lines:
            failures += 1
            print(f'CHANGED  {app.name}')
            print('\n'.join(lines))
        else:
            print(f'ok       {app.name}')
    if not args.update:
        print(f'{len(apps) - failures}/{len(apps)} apps match')
    sys.exit(1 if failures else 0)


if __name__ == '__main__':
    main()
