# -*- coding: utf_8 -*-
"""iOS app (ios/) of a Flutter project ZIP, with MobSF's iOS checks.

A Flutter project ZIP is scanned as Android source, so ios/ gets these
checks here: MobSF's Swift and Objective-C rules on the app developer's
code (CocoaPods, plugin sources, Flutter's generated files are skipped)
and the Info.plist analysis (permissions, App Transport Security, URL
schemes) of ios/Runner. High and warning items are also raised as Flutter
findings so they are not missed. MobSF's domain malware check is not run
here: the Android scan of the same ZIP already does it.
"""
import logging
import re
from pathlib import Path

from django.conf import settings

from mobsf.MobSF.security import is_pipe_or_link
from mobsf.StaticAnalyzer.views.flutter.checks import _finding
from mobsf.StaticAnalyzer.views.ios.code_analysis import merge_findings
from mobsf.StaticAnalyzer.views.ios.plist_analysis import plist_analysis
from mobsf.StaticAnalyzer.views.sast_engine import SastEngine

logger = logging.getLogger(__name__)

RULES = Path(settings.BASE_DIR) / 'StaticAnalyzer' / 'views' / 'ios' / 'rules'
# Relative to ios/: not the app developer's code
NOT_APP_CODE = ('Pods', '.symlinks', 'Flutter', 'build',
                'Runner/GeneratedPluginRegistrant')
RAISED = ('high', 'warning')


def _rules(src, rules, ext):
    options = {
        'match_rules': (RULES / rules).as_posix(),
        'match_extensions': {ext},
        'ignore_paths': [src + p for p in NOT_APP_CODE],
    }
    return SastEngine(options, src).scan()


def _url_schemes(url_types):
    schemes = set()
    for url_type in url_types or []:
        if not isinstance(url_type, dict):
            continue
        for scheme in url_type.get('CFBundleURLSchemes') or []:
            if isinstance(scheme, str):
                schemes.add(scheme)
    return sorted(schemes)


def ios_shell_analysis(checksum, root):
    """Run MobSF's iOS source checks on <root>/ios; None if there is none."""
    ios = Path(root) / 'ios'
    if is_pipe_or_link(ios) or not ios.is_dir():
        return None
    src = ios.as_posix() + '/'
    code = merge_findings(_rules(src, 'swift_rules.yaml', '.swift'),
                          _rules(src, 'objective_c_rules.yaml', '.m'))
    plist = {}
    runner = ios / 'Runner'
    # Only the app's Info.plist; plugins ship their own
    if not is_pipe_or_link(runner) and runner.is_dir():
        plist = plist_analysis(checksum, runner.as_posix() + '/', 'zip') or {}
    return {
        'code_analysis': code,
        'permissions': plist.get('permissions') or {},
        'ats_findings': (plist.get('inseccon') or {}).get(
            'ats_findings') or [],
        'url_schemes': _url_schemes(plist.get('bundle_url_types')),
    }


def _cwe(value):
    """'CWE-311: Missing ...' -> 'cwe-311' (Flutter finding format)."""
    match = re.match(r'\s*(cwe-\d{1,5})', value or '', re.IGNORECASE)
    return match.group(1).lower() if match else ''


def _masvs(value):
    """'MSTG-STORAGE-1' -> 'storage-1' (Flutter finding format)."""
    value = (value or '').strip().lower()
    return value[len('mstg-'):] if value.startswith('mstg-') else value


def _slug(text):
    return re.sub(r'[^a-z0-9]+', '_', text.lower()).strip('_')[:60]


def ios_shell_findings(shell):
    """High and warning items of the iOS app as Flutter findings."""
    if not shell:
        return []
    findings = []
    for rule, details in shell['code_analysis'].items():
        meta = details.get('metadata') or {}
        severity = meta.get('severity')
        if severity not in RAISED:
            continue
        description = meta.get('description') or rule
        findings.append(_finding(
            f'flutter_ios_{rule}', severity,
            f'iOS app: {description.splitlines()[0]}',
            f'{description} Files: {", ".join(details.get("files") or {})}',
            [], _cwe(meta.get('cwe')), _masvs(meta.get('masvs'))))
    for ats in shell['ats_findings']:
        if ats.get('severity') not in RAISED:
            continue
        issue = ats.get('issue') or ''
        findings.append(_finding(
            f'flutter_ios_ats_{_slug(issue)}', ats['severity'],
            f'iOS app: {issue}', ats.get('description') or issue,
            [], 'cwe-319', 'network-1'))
    return findings
