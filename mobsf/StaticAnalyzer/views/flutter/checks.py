# -*- coding: utf_8 -*-
"""Flutter security checks based on the packages an app uses.

Packages come from the native plugin inventory (works on obfuscated apps)
and the Dart package: URIs (non-obfuscated apps, also pure Dart packages).
Presence of a package does not prove misuse, so severities stay
conservative; protections present are reported as 'good', as MobSF does
for root detection and SSL pinning.
"""
import json
from functools import lru_cache
from pathlib import Path

DATA_FILE = Path(__file__).resolve().parent / 'flutter_check_packages.json'
SEVERITY_ORDER = {'high': 0, 'warning': 1, 'info': 2, 'good': 3}


@lru_cache(maxsize=1)
def load_check_packages():
    """Load package groups used by the checks."""
    with DATA_FILE.open(encoding='utf-8') as fobj:
        return json.load(fobj)


def _finding(fid, severity, title, description, packages, cwe, masvs):
    return {
        'id': fid,
        'severity': severity,
        'title': title,
        'description': description,
        'packages': sorted(packages),
        'cwe': cwe,
        'masvs': masvs,
    }


def flutter_checks(packages):
    """Return Flutter findings for a set of app-facing package names."""
    used = set(packages)
    groups = {k: used & set(v) for k, v in load_check_packages().items()}
    findings = []
    if groups['insecure_storage']:
        if groups['secure_storage']:
            severity = 'info'
            desc = ('The app uses unencrypted storage packages together '
                    'with encrypted storage. Ensure tokens, keys and '
                    'personal data are only stored in the encrypted '
                    'storage.')
        else:
            severity = 'warning'
            desc = ('The app uses unencrypted storage packages and no '
                    'encrypted storage package. Data written there is '
                    'stored in plaintext on the device; do not store '
                    'tokens, keys or personal data in it.')
        findings.append(_finding(
            'flutter_insecure_storage', severity,
            'Unencrypted local storage', desc,
            groups['insecure_storage'], 'cwe-312', 'storage-1'))
    if groups['secure_storage']:
        findings.append(_finding(
            'flutter_secure_storage', 'good',
            'Encrypted local storage',
            'The app uses encrypted storage (Android Keystore / iOS '
            'Keychain backed) for sensitive data.',
            groups['secure_storage'], '', 'storage-1'))
    if groups['ssl_pinning']:
        findings.append(_finding(
            'flutter_ssl_pinning', 'good',
            'SSL certificate pinning',
            'The app uses a certificate pinning package.',
            groups['ssl_pinning'], '', 'network-4'))
    else:
        findings.append(_finding(
            'flutter_no_ssl_pinning', 'info',
            'No SSL pinning package',
            'No certificate pinning package was found. Pinning can also be '
            'implemented in Dart code (SecurityContext, '
            'badCertificateCallback), which this check does not detect.',
            [], 'cwe-295', 'network-4'))
    if groups['webview']:
        findings.append(_finding(
            'flutter_webview', 'info',
            'WebView in Flutter app',
            'The app embeds a WebView. Review JavaScript settings, '
            'JavaScript channels exposed to web content and which URLs '
            'can be loaded.',
            groups['webview'], 'cwe-749', 'platform-7'))
    if groups['root_detection']:
        findings.append(_finding(
            'flutter_root_detection', 'good',
            'Root/jailbreak detection',
            'The app uses a root/jailbreak or tamper detection package.',
            groups['root_detection'], '', 'resilience-1'))
    else:
        findings.append(_finding(
            'flutter_no_root_detection', 'info',
            'No root/jailbreak detection package',
            'No root/jailbreak or tamper detection package was found.',
            [], '', 'resilience-1'))
    return sorted(
        findings, key=lambda f: (SEVERITY_ORDER[f['severity']], f['id']))


def flutter_binary_checks(deep_linking=None, js_channels=None):
    """Findings from Flutter deep linking flags and Dart API names."""
    findings = []
    if deep_linking:
        findings.append(_finding(
            'flutter_deep_linking', 'info',
            'Flutter deep linking enabled',
            'Flutter deep linking is enabled: the path of an incoming link '
            'is pushed to the app router. Ensure every reachable route '
            'validates its arguments and requires authentication where '
            'needed.',
            [], 'cwe-939', 'platform-1'))
    if js_channels:
        findings.append(_finding(
            'flutter_js_channel', 'info',
            'WebView JavaScript channel',
            'The app exposes Dart code to web content through a WebView '
            'JavaScript channel. Ensure only trusted pages are loaded and '
            'messages from the page are validated. (Detected from Dart '
            'names, which obfuscated builds remove.)',
            [], 'cwe-749', 'platform-7'))
    return sorted(
        findings, key=lambda f: (SEVERITY_ORDER[f['severity']], f['id']))


ADVISORY_SEVERITY = {'critical': 'high', 'high': 'high',
                     'medium': 'warning', 'low': 'info'}
ONE_LOWER = {'high': 'warning', 'warning': 'info', 'info': 'info'}


def flutter_build_checks(build_mode, obfuscated, advisories):
    """Findings for build mode, obfuscation and Dart SDK advisories."""
    findings = []
    if build_mode == 'debug':
        findings.append(_finding(
            'flutter_debug_build', 'high',
            'Flutter debug build',
            'The app is a Flutter debug (JIT) build. It ships the Dart '
            'kernel (kernel_blob.bin), from which the app source can be '
            'largely recovered, and debug services. Ship release builds.',
            [], 'cwe-489', 'code-2'))
    elif build_mode == 'profile':
        findings.append(_finding(
            'flutter_profile_build', 'warning',
            'Flutter profile build',
            'The app is a Flutter profile build, meant for performance '
            'testing and keeping some service extensions. Ship release '
            'builds.',
            [], 'cwe-489', 'code-2'))
    if obfuscated is False:
        findings.append(_finding(
            'flutter_not_obfuscated', 'info',
            'Dart code not obfuscated',
            'Class, function and library names are kept in the Dart '
            'snapshot, which eases reverse engineering. Build with '
            '--obfuscate --split-debug-info.',
            [], '', 'resilience-9'))
    elif obfuscated:
        findings.append(_finding(
            'flutter_obfuscated', 'good',
            'Dart code obfuscated',
            'The Dart code is obfuscated (--obfuscate).',
            [], '', 'resilience-9'))
    for adv in advisories:
        severity = ADVISORY_SEVERITY.get(adv['severity'], 'info')
        if adv['status'] != 'affected':
            severity = ONE_LOWER[severity]
        title = adv['cve'] or adv['id']
        findings.append(_finding(
            f'flutter_advisory_{adv["id"]}', severity,
            f'Dart SDK vulnerability {title} ({adv["status"]})',
            f'{adv["summary"]}. Fixed in Dart {adv["fixed_dart"]} / '
            f'Flutter {adv["fixed_flutter"]}; rebuild the app with a '
            f'patched SDK. {adv["url"]}',
            [], adv['cwe'].lower() if adv['cwe'] else '', 'code-5'))
    return sorted(
        findings, key=lambda f: (SEVERITY_ORDER[f['severity']], f['id']))
