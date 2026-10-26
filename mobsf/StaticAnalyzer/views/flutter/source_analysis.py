# -*- coding: utf_8 -*-
"""Flutter analysis entry point for Flutter project (source) ZIPs."""
import logging
import plistlib
from pathlib import Path

from defusedxml.minidom import parseString

from mobsf.MobSF.security import (
    is_path_traversal,
    is_pipe_or_link,
)
from mobsf.StaticAnalyzer.views.flutter.assets import (
    asset_secrets,
    classify_assets,
)
from mobsf.StaticAnalyzer.views.flutter.channels import source_channels
from mobsf.StaticAnalyzer.views.flutter.checks import (
    SEVERITY_ORDER,
    flutter_binary_checks,
    flutter_checks,
)
from mobsf.StaticAnalyzer.views.flutter.dart_analysis import (
    dart_code_analysis,
)
from mobsf.StaticAnalyzer.views.flutter.deeplinks import (
    android_deep_linking,
    ios_deep_linking,
)
from mobsf.StaticAnalyzer.views.flutter.fileio import (
    open_regular,
    safe_join,
)
from mobsf.StaticAnalyzer.views.flutter.osv import osv_vulnerabilities
from mobsf.StaticAnalyzer.views.flutter.plugins import app_packages
from mobsf.StaticAnalyzer.views.flutter.source import (
    is_flutter_source,
    load_yaml,
    pubspec_lock_packages,
)

logger = logging.getLogger(__name__)

MAX_CONFIG_SIZE = 1024 * 1024
MAX_ASSET_FILES = 5000
ANDROID_MANIFEST = 'android/app/src/main/AndroidManifest.xml'
IOS_INFO_PLIST = 'ios/Runner/Info.plist'
OSV_SEVERITY = {'critical': 'high', 'high': 'high', 'medium': 'warning',
                'low': 'info'}


def _read(root, rel):
    path = safe_join(root, rel)
    if path is None:
        return None
    try:
        fobj = open_regular(path, MAX_CONFIG_SIZE)
        if fobj is None:
            return None
        with fobj:
            return fobj.read(MAX_CONFIG_SIZE + 1)
    except OSError:
        return None


def _deep_linking(root):
    android = ios = None
    data = _read(root, ANDROID_MANIFEST)
    if data:
        try:
            android = android_deep_linking(parseString(data))
        except Exception:
            logger.warning('Failed to parse Flutter project manifest')
    data = _read(root, IOS_INFO_PLIST)
    if data:
        try:
            ios = ios_deep_linking(plistlib.loads(data))
        except Exception:
            logger.warning('Failed to parse Flutter project Info.plist')
    return {'android': android, 'ios': ios}


def _declared_assets(root):
    """Files listed under flutter: assets: in pubspec.yaml."""
    data = load_yaml(root / 'pubspec.yaml')
    flutter = data.get('flutter') if isinstance(data, dict) else None
    entries = flutter.get('assets') if isinstance(flutter, dict) else None
    files = []
    for entry in entries if isinstance(entries, list) else []:
        if isinstance(entry, dict):
            entry = entry.get('path')
        if not isinstance(entry, str) or is_path_traversal(entry):
            continue
        target = safe_join(root, entry.rstrip('/'))
        if target is None or is_pipe_or_link(target):
            continue
        if entry.endswith('/') and target.is_dir():
            # Flutter includes only the files directly in a listed dir
            for child in sorted(target.iterdir()):
                if not is_pipe_or_link(child) and child.is_file():
                    files.append(entry + child.name)
        elif target.is_file():
            files.append(entry)
        if len(files) >= MAX_ASSET_FILES:
            break
    return files[:MAX_ASSET_FILES]


def _osv_findings(osv):
    findings = []
    for pkg in osv or []:
        vulns = pkg['vulns']
        severity = min(
            (OSV_SEVERITY.get(v['severity'], 'info') for v in vulns),
            key=SEVERITY_ORDER.get)
        ids = ', '.join(
            v['aliases'][0] if v['aliases'] else v['id'] for v in vulns)
        fixed = sorted({f for v in vulns for f in v['fixed']})
        cwe = next((v['cwe'][0] for v in vulns if v['cwe']), '')
        findings.append({
            'id': f'flutter_osv_{pkg["name"]}',
            'severity': severity,
            'title': f'Vulnerable package {pkg["name"]} {pkg["version"]}',
            'description': (
                f'{pkg["name"]} {pkg["version"]} has known '
                f'vulnerabilities: {ids}. Fixed in: '
                f'{", ".join(fixed) or "no fixed version listed"}.'),
            'packages': [pkg['name']],
            'cwe': cwe.lower(),
            'masvs': 'code-5',
        })
    return findings


def flutter_source_analysis(app_dir, osv_enabled=False, osv_session=None):
    """Analyse a Flutter project.

    osv_enabled sends locked hosted package names and versions to
    api.osv.dev; callers gate it behind a setting.
    """
    app_dir = Path(app_dir)
    root = is_flutter_source(app_dir)
    if root is None:
        return {'is_flutter': False}
    packages = pubspec_lock_packages(root / 'pubspec.lock')
    osv = (osv_vulnerabilities(packages, session=osv_session)
           if osv_enabled else None)
    deep_linking = _deep_linking(root)
    assets = classify_assets(_declared_assets(root))
    findings = (flutter_checks(app_packages(p['name'] for p in packages))
                + flutter_binary_checks(
                    deep_linking=any(deep_linking.values()))
                + _osv_findings(osv))
    return {
        'is_flutter': True,
        'project_root': root.relative_to(app_dir).as_posix(),
        'packages': packages,
        'platform_channels': source_channels(root),
        'osv': osv,
        'deep_linking': deep_linking,
        'assets': assets,
        'asset_secrets': asset_secrets(root, assets),
        'code_analysis': dart_code_analysis(root),
        'findings': sorted(
            findings,
            key=lambda f: (SEVERITY_ORDER[f['severity']], f['id'])),
    }
