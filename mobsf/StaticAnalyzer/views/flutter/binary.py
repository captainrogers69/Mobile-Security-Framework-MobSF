# -*- coding: utf_8 -*-
"""Flutter analysis entry point for extracted APK/AAB/XAPK/APKS/IPA files."""
import logging

from mobsf.StaticAnalyzer.views.flutter.advisories import check_advisories
from mobsf.StaticAnalyzer.views.flutter.channels import binary_channels
from mobsf.StaticAnalyzer.views.flutter.assets import (
    asset_secrets,
    audit_assets,
)
from mobsf.StaticAnalyzer.views.flutter.checks import (
    SEVERITY_ORDER,
    flutter_binary_checks,
    flutter_build_checks,
    flutter_checks,
)
from mobsf.StaticAnalyzer.views.flutter.deeplinks import (
    android_deep_linking,
    ios_deep_linking,
)
from mobsf.StaticAnalyzer.views.flutter.detect import detect_flutter
from mobsf.StaticAnalyzer.views.flutter.engine import flutter_engine_info
from mobsf.StaticAnalyzer.views.flutter.fileio import safe_join
from mobsf.StaticAnalyzer.views.flutter.obfuscation import obfuscation_info
from mobsf.StaticAnalyzer.views.flutter.plugins import (
    flutter_plugins,
    mobile_packages,
)
from mobsf.StaticAnalyzer.views.flutter.snapshot import read_snapshot_header
from mobsf.StaticAnalyzer.views.flutter.symbols import uses_js_channels
from mobsf.StaticAnalyzer.views.flutter.versions import (
    dart_version,
    narrow_dart,
)

logger = logging.getLogger(__name__)
BUILD_MODES = ('debug', 'profile', 'release')


def flutter_binary_analysis(app_dir, rel_paths, platform,
                            parsed_manifest=None, info_plist=None):
    """Analyse an extracted Flutter app.

    rel_paths: files relative to app_dir. platform: 'android' or 'ios'.
    parsed_manifest: AndroidManifest.xml as parsed by MobSF (minidom).
    info_plist: the app Info.plist as a dict.
    """
    rel_paths = list(rel_paths)
    det = detect_flutter(rel_paths)
    if not det['is_flutter']:
        return {'is_flutter': False}
    build_mode = det['build_mode']
    snapshot = (safe_join(app_dir, det['app_snapshot'][0])
                if det['app_snapshot'] else None)
    header = read_snapshot_header(snapshot) if snapshot else None
    versions = dart_version(header['snapshot_hash']) if header else None
    engine = (flutter_engine_info(app_dir, det['engine'][0])
              if det['engine'] else None) or {}
    # iOS Flutter.framework knows debug/profile/release precisely
    if build_mode != 'debug' and engine.get('build_mode') in BUILD_MODES:
        build_mode = engine['build_mode']
    flutter = engine.get('flutter') or []
    dart = narrow_dart(versions['dart'] if versions else [], flutter)
    advisories = check_advisories(platform, dart=dart, flutter=flutter)
    obf = (obfuscation_info(snapshot, header['features'])
           if header else {'split_debug_info': None, 'obfuscated': None,
                           'packages': []})
    plugins = flutter_plugins(app_dir, rel_paths)
    packages = mobile_packages(
        [p['name'] for p in plugins] + obf['packages'])
    if platform == 'android':
        deep_linking = android_deep_linking(parsed_manifest)
    else:
        deep_linking = ios_deep_linking(info_plist)
    js_channels = uses_js_channels(snapshot) if snapshot else None
    assets = audit_assets(rel_paths)
    findings = (flutter_build_checks(build_mode, obf['obfuscated'], advisories)
                + flutter_checks(packages)
                + flutter_binary_checks(deep_linking, js_channels))
    return {
        'is_flutter': True,
        'platform': platform,
        'build_mode': build_mode,
        'abis': det['abis'],
        'engine_files': det['engine'],
        'snapshots': det['app_snapshot'],
        'debug_artifacts': det['debug_artifacts'],
        'snapshot_hash': header['snapshot_hash'] if header else None,
        'snapshot_features': header['features'] if header else [],
        'dart': dart,
        'engine': engine.get('engine'),
        'flutter': flutter,
        'advisories': advisories,
        'split_debug_info': obf['split_debug_info'],
        'obfuscated': obf['obfuscated'],
        'plugins': plugins,
        'packages': packages,
        'platform_channels': binary_channels(
            app_dir, rel_paths, snapshot, packages),
        'deep_linking': deep_linking,
        'js_channels': js_channels,
        'assets': assets,
        'asset_secrets': asset_secrets(app_dir, assets),
        'findings': sorted(
            findings,
            key=lambda f: (SEVERITY_ORDER[f['severity']], f['id'])),
    }
