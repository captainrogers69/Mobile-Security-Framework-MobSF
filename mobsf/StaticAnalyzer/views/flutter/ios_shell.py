# -*- coding: utf_8 -*-
"""iOS app (ios/) of a Flutter project ZIP, with MobSF's iOS checks.

A Flutter project ZIP is scanned as Android source, so ios/ gets the
offline checks MobSF runs on an iOS project ZIP, shown in the Flutter
section: Swift and Objective-C rules, iOS API rules, URLs and emails,
hardcoded secrets (code strings and plists) on the app developer's code
(CocoaPods, plugin sources, Flutter's generated files are skipped), and
the Info.plist analysis (permissions, App Transport Security, URL
schemes) of ios/Runner. High and warning items are also raised as
Flutter findings so they are not missed. MobSF's network checks (domain
malware check, App Store lookup) are not run here: the Android scan of
the same ZIP already runs the domain check.
"""
import logging
import os
import re
from pathlib import Path

from django.conf import settings

from mobsf.MobSF.security import is_pipe_or_link
from mobsf.MobSF.utils import STRINGS_REGEX
from mobsf.StaticAnalyzer.views.common.secret_detection import (
    get_secrets,
    sort_secrets,
)
from mobsf.StaticAnalyzer.views.common.shared_func import url_n_email_extract
from mobsf.StaticAnalyzer.views.flutter.checks import _finding
from mobsf.StaticAnalyzer.views.flutter.fileio import open_regular
from mobsf.StaticAnalyzer.views.ios.code_analysis import merge_findings
from mobsf.StaticAnalyzer.views.ios.plist_analysis import (
    get_plist_secrets,
    plist_analysis,
)
from mobsf.StaticAnalyzer.views.sast_engine import SastEngine

logger = logging.getLogger(__name__)

RULES = Path(settings.BASE_DIR) / 'StaticAnalyzer' / 'views' / 'ios' / 'rules'
# Relative to ios/: not the app developer's code
GENERATED = 'Runner/GeneratedPluginRegistrant'
NOT_APP_CODE = ('Pods', '.symlinks', 'Flutter', 'build', GENERATED)
RAISED = ('high', 'warning')
CODE_EXTS = ('.swift', '.m')
# As MobSF's iOS project ZIP string and secret extraction
STRING_EXTS = ('.swift', '.m', '.h', '.plist', '.json')
STRING_EXCLUDES = ('\\u0', 'com.google.')
MAX_FILES = 5000
MAX_FILE_SIZE = 1024 * 1024


def _rules(src, rules, ext):
    options = {
        'match_rules': (RULES / rules).as_posix(),
        'match_extensions': {ext} if isinstance(ext, str) else set(ext),
        'ignore_paths': [src + p for p in NOT_APP_CODE],
    }
    return SastEngine(options, src).scan()


def _app_files(src):
    """(rel path, text) of the app's own files, links and big files skipped."""
    root = Path(src)
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        prefix = '' if rel_dir == '.' else rel_dir + '/'
        dirnames[:] = sorted(d for d in dirnames
                             if f'{prefix}{d}' not in NOT_APP_CODE)
        for fname in sorted(filenames):
            rel = prefix + fname
            if (not fname.endswith(STRING_EXTS)
                    or rel.startswith(GENERATED)):
                continue
            seen += 1
            if seen > MAX_FILES:
                return
            try:
                fobj = open_regular(Path(dirpath) / fname, MAX_FILE_SIZE)
                if fobj is None:
                    continue
                with fobj:
                    text = fobj.read(MAX_FILE_SIZE + 1).decode(
                        'utf-8', 'ignore')
            except OSError:
                continue
            yield rel, text


def _urls_strings(src):
    """URLs, emails and code strings, as MobSF's iOS project ZIP scan."""
    urls, emails, strings = [], [], set()
    for rel, text in _app_files(src):
        if rel.endswith(CODE_EXTS):
            _all, url_n_file, email_n_file = url_n_email_extract(text, rel)
            urls.extend(url_n_file)
            emails.extend(email_n_file)
        for match in STRINGS_REGEX.finditer(text):
            value = match.group()
            if (len(value) >= 4 and value[0].isalnum()
                    and not any(i in value for i in STRING_EXCLUDES)):
                strings.add(value)
    return urls, emails, strings


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
    api = _rules(src, 'ios_apis.yaml', CODE_EXTS)
    urls, emails, strings = _urls_strings(src)
    secrets = set(get_secrets(strings))
    plist = {}
    runner = ios / 'Runner'
    # Only the app's Info.plist; plugins ship their own
    if not is_pipe_or_link(runner) and runner.is_dir():
        runner_src = runner.as_posix() + '/'
        plist = plist_analysis(checksum, runner_src, 'zip') or {}
        secrets.update(get_plist_secrets(checksum, runner_src))
    return {
        'code_analysis': code,
        'api': api,
        'urls': urls,
        'emails': emails,
        'secrets': sort_secrets(secrets),
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
