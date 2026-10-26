"""Unit tests for Flutter detection."""
import io
import json
import os
import plistlib
import random
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from unittest import mock

from defusedxml.minidom import parseString

import requests

from django.conf import settings
from django.core.management import call_command
from django.db.utils import OperationalError
from django.template.loader import render_to_string
from django.test import SimpleTestCase, override_settings

from mobsf.MobSF.utils import scan_state_file
from mobsf.StaticAnalyzer.views.common.appsec import get_android_dashboard
from mobsf.StaticAnalyzer.views.android.apk import valid_source_code
from mobsf.StaticAnalyzer.views.common.binary.elf import ELFChecksec
from mobsf.StaticAnalyzer.views.flutter.advisories import (
    check_advisories,
    load_advisories,
)
from mobsf.StaticAnalyzer.views.flutter.assets import (
    asset_secrets,
    audit_assets,
    classify_assets,
)
from mobsf.StaticAnalyzer.views.flutter.binary import flutter_binary_analysis
from mobsf.StaticAnalyzer.views.flutter.channels import (
    binary_channels,
    source_channels,
)
from mobsf.StaticAnalyzer.views.flutter.checks import (
    flutter_binary_checks,
    flutter_build_checks,
    flutter_checks,
    load_check_packages,
)
from mobsf.StaticAnalyzer.views.flutter.cli import scan_path
from mobsf.StaticAnalyzer.views.flutter.dart_analysis import (
    dart_code_analysis,
    load_dart_rules,
)
from mobsf.StaticAnalyzer.views.flutter.deeplinks import (
    android_deep_linking,
    ios_deep_linking,
)
from mobsf.StaticAnalyzer.views.flutter.detect import (
    detect_flutter,
    flutter_from_dir,
)
from mobsf.StaticAnalyzer.views.flutter.engine import (
    REV_RE,
    engine_revisions,
    flutter_engine_info,
    flutter_from_engine,
    flutter_from_framework_plist,
    load_flutter_engines,
)
from mobsf.StaticAnalyzer.views.flutter.ios_shell import (
    ios_shell_analysis,
    ios_shell_findings,
)
from mobsf.StaticAnalyzer.views.flutter.integration import (
    appsec_findings,
    load_result,
    save_result,
    scan_binary,
    scan_source,
)
from mobsf.StaticAnalyzer.views.flutter.obfuscation import (
    obfuscation_info,
    package_uris,
    split_debug_info,
)
from mobsf.StaticAnalyzer.views.flutter.osv import osv_vulnerabilities
from mobsf.StaticAnalyzer.views.flutter.plugins import (
    app_packages,
    base_package,
    flutter_plugins,
    mobile_packages,
)
from mobsf.StaticAnalyzer.views.flutter.symbols import uses_js_channels
from mobsf.StaticAnalyzer.views.flutter.source import (
    is_flutter_source,
    pubspec_lock_packages,
)
from mobsf.StaticAnalyzer.views.flutter.source_analysis import (
    flutter_source_analysis,
)
from mobsf.StaticAnalyzer.views.flutter.sarif import (
    redact_secret,
    to_sarif,
)
from mobsf.StaticAnalyzer.views.flutter.snapshot import (
    read_snapshot_header,
)
from mobsf.StaticAnalyzer.views.flutter.versions import (
    dart_for_flutter,
    dart_version,
    load_dart_versions,
    load_flutter_dart,
    narrow_dart,
)


APK_RELEASE = [
    'AndroidManifest.xml',
    'classes.dex',
    'lib/arm64-v8a/libflutter.so',
    'lib/arm64-v8a/libapp.so',
    'assets/flutter_assets/AssetManifest.json',
]
APK_DEBUG = [
    'AndroidManifest.xml',
    'lib/x86_64/libflutter.so',
    'assets/flutter_assets/kernel_blob.bin',
    'assets/flutter_assets/isolate_snapshot_data',
    'assets/flutter_assets/vm_snapshot_data',
]
IPA_RELEASE = [
    'Payload/Runner.app/Runner',
    'Payload/Runner.app/Frameworks/Flutter.framework/Flutter',
    'Payload/Runner.app/Frameworks/App.framework/App',
    'Payload/Runner.app/Frameworks/App.framework/flutter_assets/'
    'AssetManifest.json',
]


class DetectFlutterTests(SimpleTestCase):

    def test_non_flutter_app(self):
        res = detect_flutter(['AndroidManifest.xml', 'lib/arm64-v8a/libfoo.so'])
        self.assertFalse(res['is_flutter'])
        self.assertEqual(res['build_mode'], 'unknown')

    def test_android_release(self):
        res = detect_flutter(APK_RELEASE)
        self.assertTrue(res['is_flutter'])
        self.assertEqual(res['build_mode'], 'release')
        self.assertEqual(res['abis'], ['arm64-v8a'])
        self.assertEqual(res['engine'], ['lib/arm64-v8a/libflutter.so'])
        self.assertEqual(res['app_snapshot'], ['lib/arm64-v8a/libapp.so'])
        self.assertEqual(res['debug_artifacts'], [])

    def test_android_debug(self):
        res = detect_flutter(APK_DEBUG)
        self.assertTrue(res['is_flutter'])
        self.assertEqual(res['build_mode'], 'debug')
        self.assertEqual(
            res['debug_artifacts'],
            ['assets/flutter_assets/kernel_blob.bin'])

    def test_kernel_blob_wins_over_aot_snapshot(self):
        res = detect_flutter(
            APK_RELEASE + ['assets/flutter_assets/kernel_blob.bin'])
        self.assertEqual(res['build_mode'], 'debug')

    def test_all_abis_and_split_apks(self):
        res = detect_flutter([
            'lib/armeabi-v7a/libflutter.so',
            'lib/armeabi-v7a/libapp.so',
            'split_apks/config.arm64_v8a/lib/arm64-v8a/libflutter.so',
            'split_apks/config.arm64_v8a/lib/arm64-v8a/libapp.so',
            'split_apks/config.x86_64/lib/x86_64/libapp.so',
        ])
        self.assertEqual(res['abis'], ['arm64-v8a', 'armeabi-v7a', 'x86_64'])
        self.assertEqual(len(res['app_snapshot']), 3)
        self.assertEqual(len(res['engine']), 2)

    def test_ios_release(self):
        res = detect_flutter(IPA_RELEASE)
        self.assertTrue(res['is_flutter'])
        self.assertEqual(res['build_mode'], 'release')
        self.assertEqual(
            res['engine'],
            ['Payload/Runner.app/Frameworks/Flutter.framework/Flutter'])
        self.assertEqual(
            res['app_snapshot'],
            ['Payload/Runner.app/Frameworks/App.framework/App'])
        self.assertEqual(res['abis'], [])

    def test_ios_debug(self):
        res = detect_flutter([
            'Payload/Runner.app/Frameworks/Flutter.framework/Flutter',
            'Payload/Runner.app/Frameworks/App.framework/App',
            'Payload/Runner.app/Frameworks/App.framework/flutter_assets/'
            'kernel_blob.bin',
        ])
        self.assertEqual(res['build_mode'], 'debug')

    def test_flutter_assets_alone_detects(self):
        res = detect_flutter(['assets/flutter_assets/AssetManifest.json'])
        self.assertTrue(res['is_flutter'])
        self.assertEqual(res['build_mode'], 'unknown')

    def test_libapp_alone_is_not_flutter(self):
        res = detect_flutter(['lib/arm64-v8a/libapp.so'])
        self.assertFalse(res['is_flutter'])

    def test_exact_name_match_only(self):
        res = detect_flutter([
            'lib/arm64-v8a/libflutter.so.bak',
            'lib/arm64-v8a/notlibflutter.so',
            'assets/my_flutter_assets/x.json',
            'assets/kernel_blob.bin',
        ])
        self.assertFalse(res['is_flutter'])
        self.assertEqual(res['debug_artifacts'], [])

    def test_windows_separators(self):
        res = detect_flutter(['lib\\arm64-v8a\\libflutter.so'])
        self.assertTrue(res['is_flutter'])
        self.assertEqual(res['engine'], ['lib/arm64-v8a/libflutter.so'])


class FlutterFromDirTests(SimpleTestCase):

    def test_walks_extracted_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            for rel in APK_RELEASE:
                path = Path(tmp) / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'')
            res = flutter_from_dir(tmp)
        self.assertTrue(res['is_flutter'])
        self.assertEqual(res['build_mode'], 'release')
        self.assertEqual(res['engine'], ['lib/arm64-v8a/libflutter.so'])

    def test_missing_dir(self):
        res = flutter_from_dir('/nonexistent/mobsf/flutter/dir')
        self.assertFalse(res['is_flutter'])

    def test_does_not_follow_symlinked_dirs(self):
        with tempfile.TemporaryDirectory() as tmp, \
                tempfile.TemporaryDirectory() as outside:
            lib = Path(outside) / 'arm64-v8a'
            lib.mkdir()
            (lib / 'libflutter.so').write_bytes(b'')
            try:
                os.symlink(outside, Path(tmp) / 'lib')
            except (OSError, NotImplementedError):
                self.skipTest('symlinks not supported')
            res = flutter_from_dir(tmp)
        self.assertFalse(res['is_flutter'])


SNAP_HASH = '0123456789abcdef0123456789abcdef'
SNAP_HASH_B = SNAP_HASH.encode()
# Dart SDK 3.12.2 / Flutter 3.44.9 release APK
SDK_3_12_HASH = 'ace654289f5abc240509fc941453ebc5'
SNAP_FEATURES = b'product no-code_comments arm64 android compressed-pointers'


def _snapshot(snap_hash=SNAP_HASH_B, features=SNAP_FEATURES):
    """Build a Dart snapshot header: magic, length, kind, hash, features."""
    return (b'\xf5\xf5\xdc\xdc' + b'\x00' * 16
            + snap_hash + features + b'\x00')


class SnapshotHeaderTests(SimpleTestCase):

    def _write(self, tmp, data, name='libapp.so'):
        path = Path(tmp) / name
        path.write_bytes(data)
        return path

    def test_reads_hash_and_features(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, os.urandom(4096) + _snapshot())
            res = read_snapshot_header(path)
        self.assertEqual(res['snapshot_hash'], SNAP_HASH)
        self.assertEqual(
            res['features'],
            ['product', 'no-code_comments', 'arm64', 'android',
             'compressed-pointers'])

    def test_no_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, b'\x7fELF' + b'\x00' * 4096)
            self.assertIsNone(read_snapshot_header(path))

    def test_skips_magic_with_invalid_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = _snapshot(snap_hash=b'Z' * 32)
            path = self._write(tmp, bad + b'\x00' * 64 + _snapshot())
            res = read_snapshot_header(path)
        self.assertEqual(res['snapshot_hash'], SNAP_HASH)

    def test_header_across_chunk_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, b'\x00' * 1000 + _snapshot())
            res = read_snapshot_header(path, chunk_size=1010)
        self.assertEqual(res['snapshot_hash'], SNAP_HASH)

    def test_truncated_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, _snapshot()[:40])
            self.assertIsNone(read_snapshot_header(path))

    def test_non_printable_features_dropped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(
                tmp, _snapshot(features=b'arm64 \x1b[31mevil <b>'))
            res = read_snapshot_header(path)
        self.assertEqual(res['snapshot_hash'], SNAP_HASH)
        self.assertEqual(res['features'], ['arm64'])

    def test_unterminated_features_capped(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = _snapshot()[:52] + b'a' * 100000
            path = self._write(tmp, data)
            res = read_snapshot_header(path)
        self.assertEqual(res['snapshot_hash'], SNAP_HASH)
        self.assertLessEqual(sum(len(f) for f in res['features']), 1024)

    def test_file_over_size_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, _snapshot() + b'\x00' * 100)
            self.assertIsNone(read_snapshot_header(path, max_size=50))

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = self._write(tmp, _snapshot(), name='real.so')
            link = Path(tmp) / 'libapp.so'
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest('symlinks not supported')
            self.assertIsNone(read_snapshot_header(link))

    def test_fifo_rejected(self):
        if not hasattr(os, 'mkfifo'):
            self.skipTest('mkfifo not supported')
        with tempfile.TemporaryDirectory() as tmp:
            fifo = Path(tmp) / 'libapp.so'
            os.mkfifo(fifo)
            # Would block forever if opened
            self.assertIsNone(read_snapshot_header(fifo))

    def test_missing_file(self):
        self.assertIsNone(read_snapshot_header('/nonexistent/libapp.so'))


class DartVersionTests(SimpleTestCase):

    def test_known_hash(self):
        res = dart_version(SDK_3_12_HASH)
        self.assertEqual(res['dart'], ['3.12.1', '3.12.2'])
        self.assertIn('3.44.9', res['flutter'])

    def test_unknown_hash(self):
        self.assertIsNone(dart_version('f' * 32))

    def test_invalid_input(self):
        for bad in (None, '', 'ACE654289F5ABC240509FC941453EBC5', 42,
                    '../../etc/passwd', SDK_3_12_HASH + 'x'):
            self.assertIsNone(dart_version(bad))

    def test_table_integrity(self):
        semver = re.compile(r'^\d+\.\d+\.\d+$')
        seen = set()
        table = load_dart_versions()
        self.assertGreater(len(table), 20)
        for snap_hash, entry in table.items():
            self.assertRegex(snap_hash, r'^[0-9a-f]{32}$')
            self.assertTrue(entry['dart'])
            for ver in entry['dart'] + entry['flutter']:
                self.assertRegex(ver, semver)
            # A Dart release has exactly one snapshot hash
            self.assertFalse(seen & set(entry['dart']))
            seen |= set(entry['dart'])

    def test_dart_for_flutter(self):
        self.assertEqual(dart_for_flutter(['3.27.4']), ['3.6.2'])
        self.assertEqual(dart_for_flutter(['3.10.6']), ['3.0.6'])
        self.assertEqual(dart_for_flutter(['3.0.5']), ['2.17.6'])
        self.assertEqual(
            dart_for_flutter(['3.27.3', '3.27.4']), ['3.6.1', '3.6.2'])
        self.assertEqual(dart_for_flutter(['9.9.9']), [])
        self.assertEqual(dart_for_flutter([]), [])
        self.assertEqual(dart_for_flutter(None), [])

    def test_narrow_dart(self):
        snap = ['3.6.0', '3.6.1', '3.6.2']
        # Exact Flutter version: its Dart release
        self.assertEqual(narrow_dart(snap, ['3.27.4']), ['3.6.2'])
        # Flutter unknown: snapshot list unchanged
        self.assertEqual(narrow_dart(snap, []), snap)
        self.assertEqual(narrow_dart(snap, ['9.9.9']), snap)
        # Conflicting sources: keep the snapshot list
        self.assertEqual(narrow_dart(snap, ['3.10.6']), snap)
        # No snapshot (debug build): Dart from the Flutter version
        self.assertEqual(narrow_dart([], ['3.27.4']), ['3.6.2'])

    def test_flutter_dart_table_integrity(self):
        semver = re.compile(r'^\d+\.\d+\.\d+$')
        table = load_flutter_dart()
        self.assertGreater(len(table), 100)
        for flutter, dart in table.items():
            self.assertRegex(flutter, semver)
            self.assertRegex(dart, semver)


FA = 'assets/flutter_assets/'
IOS_FA = 'Payload/Runner.app/Frameworks/App.framework/flutter_assets/'


class AssetAuditTests(SimpleTestCase):

    def _types(self, paths):
        return {f['file']: f['type'] for f in audit_assets(paths)}

    def test_env_files(self):
        res = self._types([
            FA + '.env', FA + '.env.production', FA + 'config/prod.env',
            IOS_FA + '.env'])
        self.assertEqual(set(res.values()), {'env'})
        self.assertEqual(len(res), 4)

    def test_firebase_configs(self):
        res = self._types([
            FA + 'google-services.json',
            FA + 'GoogleService-Info.plist',
            FA + 'assets/firebase_options.json'])
        self.assertEqual(set(res.values()), {'firebase'})
        self.assertEqual(len(res), 3)

    def test_keys_not_covered_elsewhere(self):
        res = self._types([
            FA + 'AuthKey_ABC123.p8', FA + 'release.keystore',
            FA + 'ssh/id_rsa', FA + 'id_ed25519'])
        self.assertEqual(set(res.values()), {'key'})
        self.assertEqual(len(res), 4)

    def test_cert_extensions_left_to_existing_check(self):
        # .pem/.key/.p12/.jks are already reported by
        # get_hardcoded_cert_keystore
        self.assertEqual(audit_assets([
            FA + 'cert.pem', FA + 'private.key', FA + 'store.jks',
            FA + 'client.p12']), [])

    def test_named_config_files(self):
        res = self._types([
            FA + 'assets/config.json', FA + 'assets/secrets.yaml',
            FA + 'assets/api_keys.json', FA + 'credentials.xml'])
        self.assertEqual(set(res.values()), {'config'})
        self.assertEqual(len(res), 4)

    def test_generic_json_not_flagged(self):
        self.assertEqual(audit_assets([
            FA + 'assets/translations/en.json',
            FA + 'assets/animations/loading.json']), [])

    def test_databases(self):
        res = self._types([
            FA + 'assets/app.db', FA + 'data.sqlite', FA + 'seed.sqlite3',
            FA + 'cache.realm', FA + 'box.hive'])
        self.assertEqual(set(res.values()), {'database'})
        self.assertEqual(len(res), 5)

    def test_framework_files_ignored(self):
        self.assertEqual(audit_assets([
            FA + 'AssetManifest.json', FA + 'AssetManifest.bin',
            FA + 'FontManifest.json', FA + 'NOTICES.Z',
            FA + 'NativeAssetsManifest.json',
            FA + 'shaders/ink_sparkle.frag',
            FA + 'fonts/MaterialIcons-Regular.otf',
            FA + 'packages/cupertino_icons/assets/CupertinoIcons.ttf',
            FA + 'kernel_blob.bin']), [])

    def test_only_inside_flutter_assets(self):
        self.assertEqual(audit_assets([
            '.env', 'assets/.env', 'res/raw/config.json']), [])

    def test_sorted_and_unique(self):
        res = audit_assets([FA + 'b.env', FA + 'a.env', FA + 'a.env'])
        self.assertEqual([f['file'] for f in res], [FA + 'a.env', FA + 'b.env'])


# Built at runtime so secret scanners do not flag this test file
FAKE_GH_TOKEN = 'ghp' + '_' + 'A1b2C3d4E5' * 3 + 'F6g7H8'


class AssetSecretTests(SimpleTestCase):

    def _scan(self, files, audit=None, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            for rel, data in files.items():
                path = Path(tmp) / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data.encode() if isinstance(data, str)
                                 else data)
            if audit is None:
                audit = audit_assets(list(files))
            res = asset_secrets(tmp, audit, **kwargs)
        return {r['file']: r['secrets'] for r in res}

    def test_env_key_value(self):
        res = self._scan({FA + '.env': 'API_KEY=abc123\nDEBUG=true\n'})
        self.assertEqual(res[FA + '.env'], ['"API_KEY" : "abc123"'])

    def test_known_secret_format_under_any_key(self):
        res = self._scan({FA + '.env': f'SOMETHING={FAKE_GH_TOKEN}\n'})
        self.assertIn(f'GitHub token: {FAKE_GH_TOKEN}', res[FA + '.env'])

    def test_nested_json(self):
        res = self._scan({
            FA + 'firebase_options.json':
            '{"android": {"apiKey": "AIzaSyFAKEFAKE", "appId": "1:2:x"}}'})
        self.assertEqual(
            res[FA + 'firebase_options.json'],
            ['"apiKey" : "AIzaSyFAKEFAKE"'])

    def test_plist_pairs(self):
        res = self._scan({
            FA + 'GoogleService-Info.plist':
            '<dict><key>API_KEY</key>\n<string>AIzaPlist</string>'
            '<key>BUNDLE_ID</key><string>com.x</string></dict>'})
        self.assertEqual(
            res[FA + 'GoogleService-Info.plist'],
            ['"API_KEY" : "AIzaPlist"'])

    def test_yaml(self):
        res = self._scan({FA + 'secrets.yaml': 'token: "t0k3n"\nname: x\n'})
        self.assertEqual(res[FA + 'secrets.yaml'], ['"token" : "t0k3n"'])

    def test_value_with_space_not_secret(self):
        res = self._scan({FA + '.env': 'API_KEY=enter your key here\n'})
        self.assertEqual(res, {})

    def test_database_not_read(self):
        res = self._scan({FA + 'app.db': f'API_KEY={FAKE_GH_TOKEN}\n'})
        self.assertEqual(res, {})

    def test_traversal_entry_skipped(self):
        with tempfile.TemporaryDirectory() as root:
            outside = Path(root) / 'outside' / 'flutter_assets'
            outside.mkdir(parents=True)
            (outside / '.env').write_text('API_KEY=leak\n')
            base = Path(root) / 'app'
            base.mkdir()
            audit = [{'file': '../outside/flutter_assets/.env',
                      'type': 'env'}]
            self.assertEqual(asset_secrets(base, audit), [])

    def test_symlinked_asset_skipped(self):
        with tempfile.TemporaryDirectory() as root:
            secret = Path(root) / 'host.env'
            secret.write_text('API_KEY=leak\n')
            base = Path(root) / 'app'
            (base / FA).mkdir(parents=True)
            try:
                os.symlink(secret, base / FA / '.env')
            except (OSError, NotImplementedError):
                self.skipTest('symlinks not supported')
            audit = [{'file': FA + '.env', 'type': 'env'}]
            self.assertEqual(asset_secrets(base, audit), [])

    def test_oversized_asset_skipped(self):
        res = self._scan(
            {FA + '.env': 'API_KEY=abc123\n' + 'x' * 100}, max_size=20)
        self.assertEqual(res, {})

    def test_binary_garbage_tolerated(self):
        res = self._scan({FA + '.env': b'\xff\xfe\x00API_KEY=abc\n\x80'})
        self.assertEqual(res[FA + '.env'], ['"API_KEY" : "abc"'])


class _FakeSymbol:

    def __init__(self, name, value):
        self.name = name
        self.value = value


class _FakeLiefELF:
    """Stand-in for a parsed lief ELF: fixed strings and dynamic symbols."""

    def __init__(self, strings, exports=()):
        self.strings = strings
        self.dynamic_symbols = [_FakeSymbol(n, 0x1000) for n in exports]

    def get_symbol(self, name):
        for sym in self.dynamic_symbols:
            if sym.name == name:
                return sym
        raise Exception('no symbol')


# Dynamic symbols exported by a real Flutter 3.44 libapp.so
LIBAPP_EXPORTS = (
    '_kDartVmSnapshotInstructions', '_kDartVmSnapshotData',
    '_kDartIsolateSnapshotInstructions', '_kDartIsolateSnapshotData')


class ELFDartStringsTests(SimpleTestCase):
    """Dart strings in libapp.so are not C strings; lief misses them."""

    def _checksec(self, tmp, lief_strings, exports=()):
        path = Path(tmp) / 'libapp.so'
        # Dart string objects: no NUL terminator, separated by headers
        path.write_bytes(
            b'\x7fELF\x02\x01\x01' + b'\x00' * 57
            + b'\x02\x00\x00\x00https://dart-only.example/api'
            + b'\x04\x00\x00\x00' + FAKE_GH_TOKEN.encode() + b'\x01\x02')
        chk = ELFChecksec.__new__(ELFChecksec)
        chk.elf_path = path.as_posix()
        chk.elf_rel = 'lib/arm64-v8a/libapp.so'
        chk.elf = _FakeLiefELF(lief_strings, exports)
        return chk

    def test_dart_snapshot_includes_os_strings(self):
        with tempfile.TemporaryDirectory() as tmp:
            chk = self._checksec(
                tmp, ['GLIBC'], exports=LIBAPP_EXPORTS)
            self.assertTrue(chk.is_dart())
            strings = chk.strings()
        self.assertIn('GLIBC', strings)
        self.assertTrue(
            any('https://dart-only.example/api' in s for s in strings))
        self.assertTrue(any(FAKE_GH_TOKEN in s for s in strings))

    def test_flutter_engine_keeps_lief_strings(self):
        # libflutter.so names the snapshot symbols but does not export them
        with tempfile.TemporaryDirectory() as tmp:
            chk = self._checksec(
                tmp, ['_kDartVmSnapshotInstructions', 'Dart_Cleanup'])
            self.assertTrue(chk.is_dart())
            strings = chk.strings()
        self.assertEqual(
            sorted(strings), ['Dart_Cleanup', '_kDartVmSnapshotInstructions'])

    def test_non_dart_binary_keeps_lief_strings(self):
        with tempfile.TemporaryDirectory() as tmp:
            chk = self._checksec(tmp, ['GLIBC', 'malloc'])
            self.assertFalse(chk.is_dart())
            strings = chk.strings()
        self.assertEqual(sorted(strings), ['GLIBC', 'malloc'])

    def test_no_lief_strings_falls_back_to_os_strings(self):
        with tempfile.TemporaryDirectory() as tmp:
            chk = self._checksec(tmp, [])
            strings = chk.strings()
        self.assertTrue(
            any('https://dart-only.example/api' in s for s in strings))


# Engine revision of Flutter 3.44.9 (bin/internal/engine.version)
ENGINE_3_44_9 = '5a2a6a42cce67f965cf540fcecf616faca624aa1'
# Other 40-hex strings seen in a real libflutter.so
DECOY_REVS = ('80743bd43fd5b38fedc503308e7a652e23d3ec93', '8' * 40)


class FlutterEngineTests(SimpleTestCase):

    def _write(self, tmp, data):
        path = Path(tmp) / 'libflutter.so'
        path.write_bytes(data)
        return path

    def test_revisions_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(
                tmp, b'\x00\x01' + ENGINE_3_44_9.encode() + b'\x00junk\x00'
                + DECOY_REVS[0].encode() + b'\x00')
            revs = engine_revisions(path)
        self.assertEqual(revs, {ENGINE_3_44_9, DECOY_REVS[0]})

    def test_longer_hex_runs_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, b'\x00' + b'a' * 41 + b'\x00'
                               + b'x' + ENGINE_3_44_9.encode() + b'\x00')
            self.assertEqual(engine_revisions(path), set())

    def test_revision_across_chunk_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(
                tmp, b'\x00' * 990 + ENGINE_3_44_9.encode() + b'\x00')
            revs = engine_revisions(path, chunk_size=1000)
        self.assertEqual(revs, {ENGINE_3_44_9})

    def test_chunked_scan_matches_whole_file(self):
        rng = random.Random(7)
        alphabet = b'0123456789abcdefxyz\x00 '
        hexdigits = b'0123456789abcdef'
        with tempfile.TemporaryDirectory() as tmp:
            for _ in range(100):
                data = bytes(rng.choice(alphabet)
                             for _ in range(rng.randint(0, 300)))
                pos = rng.randint(0, len(data))
                run = bytes(rng.choice(hexdigits)
                            for _ in range(rng.choice((39, 40, 41))))
                data = data[:pos] + run + data[pos:]
                path = self._write(tmp, data)
                want = {m.group().decode() for m in REV_RE.finditer(data)}
                for size in (41, 42, 97, 1000):
                    self.assertEqual(
                        engine_revisions(path, chunk_size=size), want)

    def test_flutter_version_from_engine(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = b'\x00'.join(
                r.encode() for r in (*DECOY_REVS, ENGINE_3_44_9)) + b'\x00'
            res = flutter_from_engine(self._write(tmp, data))
        self.assertEqual(res, {'engine': ENGINE_3_44_9, 'flutter': ['3.44.9']})

    def test_unknown_engine(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, DECOY_REVS[0].encode() + b'\x00')
            self.assertIsNone(flutter_from_engine(path))

    def test_symlink_and_size_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = self._write(tmp, ENGINE_3_44_9.encode() + b'\x00')
            self.assertEqual(engine_revisions(real, max_size=10), set())
            link = Path(tmp) / 'link.so'
            try:
                os.symlink(real, link)
            except (OSError, NotImplementedError):
                self.skipTest('symlinks not supported')
            self.assertEqual(engine_revisions(link), set())

    def test_engine_table_integrity(self):
        seen = set()
        table = load_flutter_engines()
        self.assertGreater(len(table), 100)
        for rev, versions in table.items():
            self.assertRegex(rev, r'^[0-9a-f]{40}$')
            self.assertTrue(versions)
            for ver in versions:
                self.assertRegex(ver, r'^\d+\.\d+\.\d+$')
            # A Flutter release has exactly one engine revision
            self.assertFalse(seen & set(versions))
            seen |= set(versions)


TLS_GHSA = 'GHSA-frr6-h895-5pxp'


class AdvisoryTests(SimpleTestCase):

    def _ids(self, res):
        return {a['id']: a['status'] for a in res}

    def test_exact_flutter_version_affected(self):
        res = check_advisories('android', flutter=['3.44.9'])
        self.assertEqual(self._ids(res), {TLS_GHSA: 'affected'})
        self.assertEqual(res[0]['severity'], 'high')

    def test_platform_not_affected(self):
        self.assertEqual(check_advisories('ios', flutter=['3.44.9']), [])

    def test_patched_version(self):
        self.assertEqual(check_advisories('android', flutter=['3.47.8']), [])

    def test_dart_range_spanning_fix_is_possible(self):
        dart = ['3.13.%d' % i for i in range(8)]
        res = check_advisories('android', dart=dart)
        self.assertEqual(self._ids(res), {TLS_GHSA: 'possibly affected'})

    def test_old_dart_hits_runtime_cves(self):
        res = check_advisories('ios', dart=['2.15.0', '2.15.1'])
        self.assertEqual(
            self._ids(res),
            {'GHSA-c8mh-jj22-xg5h': 'affected',
             'GHSA-m9pm-2598-57rj': 'affected'})

    def test_flutter_preferred_over_dart_range(self):
        dart = ['3.13.%d' % i for i in range(8)]
        res = check_advisories('android', dart=dart, flutter=['3.47.8'])
        self.assertEqual(res, [])

    def test_unknown_version(self):
        self.assertEqual(check_advisories('android'), [])

    def test_sorted_by_severity(self):
        res = check_advisories('android', dart=['2.15.0'])
        self.assertEqual(res[0]['id'], TLS_GHSA)

    def test_advisory_file_integrity(self):
        semver = r'^\d+\.\d+\.\d+$'
        advisories = load_advisories()
        self.assertTrue(advisories)
        for adv in advisories:
            self.assertRegex(adv['fixed_dart'], semver)
            self.assertRegex(adv['fixed_flutter'], semver)
            self.assertIn(adv['severity'], ('low', 'medium', 'high',
                                            'critical'))
            self.assertTrue(set(adv['platforms']) <= {'android', 'ios'})
            self.assertTrue(adv['url'].startswith(
                'https://github.com/dart-lang/sdk/security/advisories/'
                + adv['id']))


IOS_FW = 'Payload/Runner.app/Frameworks/Flutter.framework/'


def _framework_plist(fmt=plistlib.FMT_XML, **extra):
    data = {'CFBundleExecutable': 'Flutter', 'BuildMode': 'release',
            'FlutterEngine': ENGINE_3_44_9}
    data.update(extra)
    return plistlib.dumps(data, fmt=fmt)


class IOSEngineTests(SimpleTestCase):

    def _plist(self, tmp, data):
        path = Path(tmp) / 'Info.plist'
        path.write_bytes(data)
        return path

    def test_xml_plist(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = flutter_from_framework_plist(
                self._plist(tmp, _framework_plist()))
        self.assertEqual(res, {'engine': ENGINE_3_44_9,
                               'flutter': ['3.44.9'],
                               'build_mode': 'release'})

    def test_binary_plist_profile_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = flutter_from_framework_plist(self._plist(
                tmp, _framework_plist(plistlib.FMT_BINARY,
                                      BuildMode='profile')))
        self.assertEqual(res['build_mode'], 'profile')
        self.assertEqual(res['flutter'], ['3.44.9'])

    def test_unknown_engine_keeps_build_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = flutter_from_framework_plist(self._plist(
                tmp, _framework_plist(FlutterEngine=DECOY_REVS[0])))
        self.assertEqual(res, {'engine': DECOY_REVS[0], 'flutter': [],
                               'build_mode': 'release'})

    def test_invalid_values_dropped(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = flutter_from_framework_plist(self._plist(
                tmp, _framework_plist(FlutterEngine='../../etc/passwd',
                                      BuildMode='<script>')))
        self.assertEqual(res, {'engine': None, 'flutter': [],
                               'build_mode': None})

    def test_entity_declaration_rejected(self):
        bomb = (b'<?xml version="1.0"?><!DOCTYPE plist ['
                b'<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;">]>'
                b'<plist version="1.0"><dict><key>FlutterEngine</key>'
                b'<string>&b;</string></dict></plist>')
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(
                flutter_from_framework_plist(self._plist(tmp, bomb)))

    def test_not_a_dict_or_garbage(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(flutter_from_framework_plist(
                self._plist(tmp, plistlib.dumps(['a']))))
            self.assertIsNone(flutter_from_framework_plist(
                self._plist(tmp, b'\x00\xff garbage')))

    def test_oversized_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = self._plist(tmp, _framework_plist())
            self.assertIsNone(
                flutter_from_framework_plist(real, max_size=10))
            link = Path(tmp) / 'link.plist'
            try:
                os.symlink(real, link)
            except (OSError, NotImplementedError):
                self.skipTest('symlinks not supported')
            self.assertIsNone(flutter_from_framework_plist(link))


class EngineInfoTests(SimpleTestCase):

    def _app(self, tmp, files):
        for rel, data in files.items():
            path = Path(tmp) / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)

    def test_android_engine(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._app(tmp, {'lib/arm64-v8a/libflutter.so':
                            ENGINE_3_44_9.encode() + b'\x00'})
            res = flutter_engine_info(tmp, 'lib/arm64-v8a/libflutter.so')
        self.assertEqual(res['flutter'], ['3.44.9'])

    def test_ios_engine_uses_framework_plist(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._app(tmp, {IOS_FW + 'Flutter': b'\xcf\xfa\xed\xfe',
                            IOS_FW + 'Info.plist': _framework_plist()})
            res = flutter_engine_info(tmp, IOS_FW + 'Flutter')
        self.assertEqual(res['flutter'], ['3.44.9'])
        self.assertEqual(res['build_mode'], 'release')

    def test_unsafe_paths_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(flutter_engine_info(
                tmp, '../lib/arm64-v8a/libflutter.so'))
            self.assertIsNone(flutter_engine_info(tmp, '/etc/libflutter.so'))
            self.assertIsNone(flutter_engine_info(tmp, 'lib/libfoo.so'))


DWARF = ['product', 'dwarf_stack_traces_mode', 'arm64', 'android']
NO_DWARF = ['product', 'no-dwarf_stack_traces_mode', 'arm64', 'android']


def _uris(count, pkgs=('flutter', 'http')):
    return [f'package:{pkgs[i % len(pkgs)]}/src/file_{i}.dart'
            for i in range(count)]


class ObfuscationTests(SimpleTestCase):

    def _bin(self, tmp, uris):
        path = Path(tmp) / 'libapp.so'
        path.write_bytes(b'\x00\x7fELF' + b''.join(
            b'\x02\x00' + u.encode() + b'\x00\x13' for u in uris))
        return path

    def test_split_debug_info_from_features(self):
        self.assertTrue(split_debug_info(DWARF))
        self.assertFalse(split_debug_info(NO_DWARF))
        self.assertIsNone(split_debug_info([]))
        self.assertIsNone(split_debug_info(None))

    def test_not_obfuscated_lists_packages(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = obfuscation_info(self._bin(tmp, _uris(300)), DWARF)
        self.assertEqual(res, {'split_debug_info': True,
                               'obfuscated': False,
                               'package_uris': 300,
                               'packages': ['flutter', 'http']})

    def test_obfuscated(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = obfuscation_info(self._bin(tmp, _uris(3)), DWARF)
        self.assertTrue(res['obfuscated'])
        self.assertEqual(res['package_uris'], 3)

    def test_no_dwarf_means_not_obfuscated(self):
        # Flutter only allows --obfuscate with --split-debug-info
        with tempfile.TemporaryDirectory() as tmp:
            res = obfuscation_info(self._bin(tmp, _uris(3)), NO_DWARF)
        self.assertFalse(res['split_debug_info'])
        self.assertFalse(res['obfuscated'])

    def test_unreadable_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = self._bin(tmp, _uris(300))
            link = Path(tmp) / 'link.so'
            try:
                os.symlink(real, link)
            except (OSError, NotImplementedError):
                self.skipTest('symlinks not supported')
            res = obfuscation_info(link, DWARF)
        self.assertEqual(res, {'split_debug_info': True,
                               'obfuscated': None,
                               'package_uris': 0,
                               'packages': []})

    def test_uri_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            uris = package_uris(self._bin(tmp, _uris(50)), max_uris=10)
        self.assertEqual(len(uris), 10)

    def test_non_uri_text_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'libapp.so'
            path.write_bytes(b'\x00package:Bad Name/x.dart\x00'
                             b'package:ok/no_extension\x00'
                             b'package:ok/../../etc/passwd\x00'
                             b'package:good/src/a.dart\x00')
            self.assertEqual(package_uris(path),
                             {'package:good/src/a.dart'})

    def test_chunked_scan_matches_whole_file(self):
        rng = random.Random(11)
        with tempfile.TemporaryDirectory() as tmp:
            for _ in range(60):
                parts = []
                for _ in range(rng.randint(0, 12)):
                    parts.append(bytes(rng.choice(b'abc/._\x00 ')
                                       for _ in range(rng.randint(0, 30))))
                    parts.append(rng.choice(_uris(40)).encode())
                data = b''.join(parts)
                path = Path(tmp) / 'libapp.so'
                path.write_bytes(data)
                want = package_uris(path, chunk_size=len(data) + 1)
                for size in (64, 101, 333):
                    self.assertEqual(
                        package_uris(path, chunk_size=size), want)


REG = b'Error registering plugin %s, %s'
IOS_APP = 'Payload/Runner.app/'


def _swift_class(module, cls):
    return f'_TtC{len(module)}{module}{len(cls)}{cls}'.encode()


class PluginInventoryTests(SimpleTestCase):

    def _app(self, tmp, files):
        for rel, data in files.items():
            path = Path(tmp) / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return list(files)

    def _names(self, res):
        return sorted((p['name'], p['package']) for p in res)

    def test_android_registrant(self):
        with tempfile.TemporaryDirectory() as tmp:
            rels = self._app(tmp, {
                'classes.dex': b'dex\n035\x00q' + REG % (
                    b'shared_preferences_android',
                    b'io.flutter.plugins.sharedpreferences.'
                    b'SharedPreferencesPlugin') + b'\x00',
                'classes2.dex': b'n' + REG % (
                    b'flutter_secure_storage',
                    b'com.it_nomads.fluttersecurestorage.'
                    b'FlutterSecureStoragePlugin') + b'\x00',
            })
            res = flutter_plugins(tmp, rels)
        self.assertEqual(self._names(res), [
            ('flutter_secure_storage', 'flutter_secure_storage'),
            ('shared_preferences_android', 'shared_preferences')])
        sp = [p for p in res if p['name'] == 'shared_preferences_android'][0]
        self.assertEqual(
            sp['class'],
            'io.flutter.plugins.sharedpreferences.SharedPreferencesPlugin')
        self.assertEqual(sp['platform'], 'android')

    def test_android_split_apk_dex(self):
        with tempfile.TemporaryDirectory() as tmp:
            rels = self._app(tmp, {
                'split_apks/base/classes.dex': REG % (
                    b'webview_flutter_android',
                    b'io.flutter.plugins.webviewflutter.WebViewFlutterPlugin',
                ) + b'\x00'})
            res = flutter_plugins(tmp, rels)
        self.assertEqual(self._names(res),
                         [('webview_flutter_android', 'webview_flutter')])

    def test_ios_swift_plugins_in_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            rels = self._app(tmp, {
                IOS_APP + 'Info.plist': plistlib.dumps(
                    {'CFBundleExecutable': 'Runner'},
                    fmt=plistlib.FMT_BINARY),
                IOS_APP + 'Runner': b'\xcf\xfa\xed\xfe\x00' + b'\x00'.join([
                    _swift_class('shared_preferences_foundation',
                                 'SharedPreferencesPlugin'),
                    _swift_class('webview_flutter_wkwebview',
                                 'WebViewFlutterPlugin'),
                    # Not a plugin class
                    _swift_class('flutter_secure_storage_darwin',
                                 'FlutterSecureStorage')]) + b'\x00',
            })
            res = flutter_plugins(tmp, rels)
        self.assertEqual(self._names(res), [
            ('shared_preferences_foundation', 'shared_preferences'),
            ('webview_flutter_wkwebview', 'webview_flutter')])
        self.assertTrue(all(p['platform'] == 'ios' for p in res))

    def test_ios_cocoapods_frameworks(self):
        with tempfile.TemporaryDirectory() as tmp:
            rels = self._app(tmp, {
                IOS_APP + 'Frameworks/App.framework/App': b'x',
                IOS_APP + 'Frameworks/Flutter.framework/Flutter': b'x',
                IOS_APP + 'Frameworks/url_launcher_ios.framework/'
                'url_launcher_ios': b'x',
                IOS_APP + 'Frameworks/FirebaseCore.framework/FirebaseCore':
                b'x',
            })
            res = flutter_plugins(tmp, rels)
        self.assertEqual(self._names(res),
                         [('url_launcher_ios', 'url_launcher')])

    def test_bad_mangled_lengths_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            rels = self._app(tmp, {
                IOS_APP + 'Info.plist': plistlib.dumps(
                    {'CFBundleExecutable': 'Runner'}),
                IOS_APP + 'Runner': b'_TtC99short5XPlugin\x00'
                b'_TtC3abc999Plugin\x00',
            })
            self.assertEqual(flutter_plugins(tmp, rels), [])

    def test_executable_name_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            outside = Path(tmp) / 'outside'
            outside.write_bytes(_swift_class('evil_plugin', 'EvilPlugin'))
            rels = self._app(tmp, {
                IOS_APP + 'Info.plist': plistlib.dumps(
                    {'CFBundleExecutable': '../../outside'})})
            self.assertEqual(flutter_plugins(tmp, rels), [])

    def test_rel_path_traversal_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            secret = Path(root) / 'host.dex'
            secret.write_bytes(REG % (b'evil_android', b'a.b.EvilPlugin'))
            base = Path(root) / 'app'
            base.mkdir()
            self.assertEqual(flutter_plugins(base, ['../host.dex']), [])
            try:
                os.symlink(secret, base / 'classes.dex')
            except (OSError, NotImplementedError):
                self.skipTest('symlinks not supported')
            self.assertEqual(flutter_plugins(base, ['classes.dex']), [])

    def test_base_package_names(self):
        for name, base in (('shared_preferences_android',
                            'shared_preferences'),
                           ('path_provider_foundation', 'path_provider'),
                           ('flutter_secure_storage_darwin',
                            'flutter_secure_storage'),
                           ('webview_flutter_wkwebview', 'webview_flutter'),
                           ('jni', 'jni'), ('local_auth_ios', 'local_auth')):
            self.assertEqual(base_package(name), base)


class FlutterChecksTests(SimpleTestCase):

    def _sev(self, res):
        return {f['id']: f['severity'] for f in res}

    def test_real_plugin_sample(self):
        res = flutter_checks({'shared_preferences', 'flutter_secure_storage',
                              'webview_flutter', 'jni', 'jni_flutter'})
        self.assertEqual(self._sev(res), {
            'flutter_insecure_storage': 'info',
            'flutter_secure_storage': 'good',
            'flutter_webview': 'info',
            'flutter_no_ssl_pinning': 'info',
            'flutter_no_root_detection': 'info'})

    def test_insecure_storage_without_secure_storage(self):
        res = flutter_checks({'hive'})
        storage = [f for f in res if f['id'] == 'flutter_insecure_storage'][0]
        self.assertEqual(storage['severity'], 'warning')
        self.assertEqual(storage['packages'], ['hive'])
        self.assertEqual(storage['cwe'], 'cwe-312')
        self.assertEqual(storage['masvs'], 'storage-1')

    def test_protections_present(self):
        res = flutter_checks({'freerasp', 'http_certificate_pinning'})
        self.assertEqual(self._sev(res), {
            'flutter_ssl_pinning': 'good',
            'flutter_root_detection': 'good'})

    def test_no_packages(self):
        self.assertEqual(self._sev(flutter_checks([])), {
            'flutter_no_ssl_pinning': 'info',
            'flutter_no_root_detection': 'info'})

    def test_sorted_by_severity(self):
        res = flutter_checks({'hive', 'flutter_inappwebview', 'freerasp'})
        order = ['high', 'warning', 'info', 'good']
        sev = [order.index(f['severity']) for f in res]
        self.assertEqual(sev, sorted(sev))

    def test_package_lists(self):
        groups = load_check_packages()
        for name in ('insecure_storage', 'secure_storage', 'ssl_pinning',
                     'webview', 'root_detection'):
            self.assertTrue(groups[name])
            for pkg in groups[name]:
                self.assertRegex(pkg, r'^[a-z][a-z0-9_]*$')
        self.assertFalse(set(groups['insecure_storage'])
                         & set(groups['secure_storage']))


MANIFEST = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
    'package="com.example.app"><application><activity '
    'android:name=".MainActivity">{meta}</activity></application></manifest>')
DEEPLINK_META = ('<meta-data android:name="flutter_deeplinking_enabled" '
                 'android:value="{value}" />')


class DeepLinkingTests(SimpleTestCase):

    def _manifest(self, meta=''):
        return parseString(MANIFEST.format(meta=meta))

    def test_android_flag(self):
        self.assertTrue(android_deep_linking(self._manifest(
            DEEPLINK_META.format(value='true'))))
        self.assertFalse(android_deep_linking(self._manifest(
            DEEPLINK_META.format(value='false'))))
        self.assertIsNone(android_deep_linking(self._manifest()))
        # Resource references cannot be resolved here
        self.assertIsNone(android_deep_linking(self._manifest(
            DEEPLINK_META.format(value='@bool/deeplinks'))))
        self.assertIsNone(android_deep_linking(None))

    def test_ios_flag(self):
        self.assertTrue(ios_deep_linking({'FlutterDeepLinkingEnabled': True}))
        self.assertFalse(
            ios_deep_linking({'FlutterDeepLinkingEnabled': False}))
        self.assertIsNone(ios_deep_linking({}))
        self.assertIsNone(ios_deep_linking({'FlutterDeepLinkingEnabled': 'YES'}))
        self.assertIsNone(ios_deep_linking(None))


class JSChannelTests(SimpleTestCase):

    def _bin(self, tmp, data):
        path = Path(tmp) / 'libapp.so'
        path.write_bytes(data)
        return path

    def test_channel_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(uses_js_channels(
                self._bin(tmp, b'\x00\x01addJavaScriptChannel\x00')))

    def test_channel_absent_or_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(uses_js_channels(
                self._bin(tmp, b'\x00addJavaScriptChannelX\x00'
                               b'xaddJavaScriptChannel\x00setJavaScriptMode')))

    def test_pigeon_channel_name_ignored(self):
        # webview_flutter 2.x/3.x platform channel names are string
        # literals, kept even in obfuscated apps that use no JS channel
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(uses_js_channels(self._bin(
                tmp, b'\x00dev.flutter.pigeon.WebViewHostApi.'
                     b'addJavaScriptChannel\x00')))

    def test_webview_3x_unknown(self):
        # webview_flutter 3.x always compiles in its own
        # addJavaScriptChannel, so the name does not show app usage
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(uses_js_channels(self._bin(
                tmp, b'\x00\x01addJavaScriptChannel\x00'
                     b'\x00JavascriptChannelRegistry\x00')))

    def test_unreadable(self):
        self.assertIsNone(uses_js_channels('/nonexistent/libapp.so'))


class BinaryChecksTests(SimpleTestCase):

    def test_findings(self):
        res = {f['id']: f for f in flutter_binary_checks(
            deep_linking=True, js_channels=True)}
        self.assertEqual(res['flutter_deep_linking']['severity'], 'info')
        self.assertEqual(res['flutter_deep_linking']['cwe'], 'cwe-939')
        self.assertEqual(res['flutter_deep_linking']['masvs'], 'platform-1')
        self.assertEqual(res['flutter_js_channel']['severity'], 'info')
        self.assertEqual(res['flutter_js_channel']['masvs'], 'platform-7')

    def test_no_findings_when_off_or_unknown(self):
        self.assertEqual(flutter_binary_checks(), [])
        self.assertEqual(
            flutter_binary_checks(deep_linking=False, js_channels=False), [])


PUBSPEC = """name: demo
dependencies:
  flutter:
    sdk: flutter
  http: ^1.2.0
"""
PUBSPEC_LOCK = """packages:
  http:
    dependency: "direct main"
    description:
      name: http
      url: "https://pub.dev"
    source: hosted
    version: "1.2.0"
  path:
    dependency: transitive
    description:
      name: path
      url: "https://pub.dev"
    source: hosted
    version: "1.9.0-dev.1"
  flutter:
    dependency: "direct main"
    description: flutter
    source: sdk
    version: "0.0.0"
  mylib:
    dependency: "direct main"
    description:
      path: "../mylib"
    source: path
    version: "0.1.0"
sdks:
  dart: ">=3.4.0 <4.0.0"
"""


class FlutterSourceTests(SimpleTestCase):

    def _tree(self, tmp, files):
        for rel, data in files.items():
            path = Path(tmp) / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data)

    def test_project_at_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._tree(tmp, {'pubspec.yaml': PUBSPEC, 'lib/main.dart': ''})
            self.assertEqual(is_flutter_source(tmp), Path(tmp))

    def test_project_one_level_down(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._tree(tmp, {'demo/pubspec.yaml': PUBSPEC})
            self.assertEqual(is_flutter_source(tmp), Path(tmp) / 'demo')

    def test_pure_dart_package_is_not_flutter(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._tree(tmp, {'pubspec.yaml': 'name: x\ndependencies:\n'
                                             '  http: any\n'})
            self.assertIsNone(is_flutter_source(tmp))

    def test_malformed_pubspec(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._tree(tmp, {'pubspec.yaml': 'name: [unclosed\n'})
            self.assertIsNone(is_flutter_source(tmp))

    def test_yaml_python_tags_not_executed(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._tree(tmp, {'pubspec.yaml':
                             '!!python/object/apply:os.system ["touch pwned"]\n'})
            self.assertIsNone(is_flutter_source(tmp))
            self.assertFalse((Path(tmp) / 'pwned').exists())

    def test_lock_packages(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._tree(tmp, {'pubspec.lock': PUBSPEC_LOCK})
            res = pubspec_lock_packages(Path(tmp) / 'pubspec.lock')
        self.assertEqual(res, [
            {'name': 'flutter', 'version': '0.0.0', 'source': 'sdk',
             'dependency': 'direct main'},
            {'name': 'http', 'version': '1.2.0', 'source': 'hosted',
             'dependency': 'direct main'},
            {'name': 'mylib', 'version': '0.1.0', 'source': 'path',
             'dependency': 'direct main'},
            {'name': 'path', 'version': '1.9.0-dev.1', 'source': 'hosted',
             'dependency': 'transitive'}])

    def test_lock_invalid_entries_dropped(self):
        lock = ('packages:\n'
                '  "../evil":\n    source: hosted\n    version: "1.0.0"\n'
                '  ok:\n    source: hosted\n    version: "1.0.0; rm -rf"\n'
                '  good:\n    source: hosted\n    version: "2.0.0"\n'
                '    dependency: transitive\n')
        with tempfile.TemporaryDirectory() as tmp:
            self._tree(tmp, {'pubspec.lock': lock})
            res = pubspec_lock_packages(Path(tmp) / 'pubspec.lock')
        self.assertEqual([p['name'] for p in res], ['good'])

    def test_lock_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._tree(tmp, {'pubspec.lock': PUBSPEC_LOCK})
            self.assertEqual(pubspec_lock_packages(
                Path(tmp) / 'pubspec.lock', max_size=10), [])
            self.assertEqual(
                pubspec_lock_packages(Path(tmp) / 'missing.lock'), [])


HTTP_GHSA = 'GHSA-4rgh-jx4f-qfcq'
OSV_HTTP_VULN = {
    'id': HTTP_GHSA,
    'summary': 'http before 0.13.3 vulnerable to header injection',
    'aliases': ['CVE-2020-35669'],
    'database_specific': {'severity': 'MODERATE', 'cwe_ids': ['CWE-74']},
    'affected': [{'package': {'name': 'http', 'ecosystem': 'Pub'},
                  'ranges': [{'type': 'ECOSYSTEM', 'events': [
                      {'introduced': '0'}, {'fixed': '0.13.3'}]}]}],
}


class _FakeResponse:

    def __init__(self, data, status=200):
        self.status_code = status
        self._data = json.dumps(data).encode()

    def iter_content(self, chunk_size):
        yield self._data

    def close(self):
        pass


class _FakeSession:

    def __init__(self, batch, vulns, fail=False):
        self.batch, self.vulns, self.fail = batch, vulns, fail
        self.queries, self.fetched = [], []

    def post(self, url, json=None, **kwargs):
        if self.fail:
            raise requests.ConnectionError('offline')
        self.queries.extend(json['queries'])
        return _FakeResponse(self.batch)

    def get(self, url, **kwargs):
        self.fetched.append(url)
        vid = url.rsplit('/', 1)[1]
        return _FakeResponse(self.vulns.get(vid, {}), 200 if vid in
                             self.vulns else 404)


LOCKED = [
    {'name': 'flutter', 'version': '0.0.0', 'source': 'sdk',
     'dependency': 'direct main'},
    {'name': 'http', 'version': '0.12.0', 'source': 'hosted',
     'dependency': 'direct main'},
    {'name': 'path', 'version': '1.9.0', 'source': 'hosted',
     'dependency': 'transitive'},
]


class OSVTests(SimpleTestCase):

    def test_vulnerable_package(self):
        session = _FakeSession(
            {'results': [{'vulns': [{'id': HTTP_GHSA}]}, {}]},
            {HTTP_GHSA: OSV_HTTP_VULN})
        res = osv_vulnerabilities(LOCKED, session=session)
        self.assertEqual(res, [{
            'name': 'http', 'version': '0.12.0', 'dependency': 'direct main',
            'vulns': [{
                'id': HTTP_GHSA,
                'summary': 'http before 0.13.3 vulnerable to header injection',
                'aliases': ['CVE-2020-35669'],
                'severity': 'medium',
                'cwe': ['CWE-74'],
                'fixed': ['0.13.3'],
                'url': f'https://osv.dev/vulnerability/{HTTP_GHSA}'}]}])
        # Only hosted packages are sent to OSV
        self.assertEqual([q['package']['name'] for q in session.queries],
                         ['http', 'path'])
        self.assertTrue(all(q['package']['ecosystem'] == 'Pub'
                            for q in session.queries))

    def test_no_vulns(self):
        session = _FakeSession({'results': [{}, {}]}, {})
        self.assertEqual(osv_vulnerabilities(LOCKED, session=session), [])

    def test_network_error_returns_none(self):
        session = _FakeSession({}, {}, fail=True)
        self.assertIsNone(osv_vulnerabilities(LOCKED, session=session))

    def test_malformed_batch_returns_none(self):
        for bad in ({'results': 'x'}, {'results': [{}]}, ['x'], {}):
            session = _FakeSession(bad, {})
            self.assertIsNone(osv_vulnerabilities(LOCKED, session=session))

    def test_unsafe_vuln_ids_not_fetched(self):
        session = _FakeSession(
            {'results': [{'vulns': [{'id': '../../admin'},
                                    {'id': 'x' * 200}]}, {}]}, {})
        self.assertEqual(osv_vulnerabilities(LOCKED, session=session), [])
        self.assertEqual(session.fetched, [])

    def test_nothing_to_query(self):
        session = _FakeSession({}, {})
        self.assertEqual(osv_vulnerabilities(LOCKED[:1], session=session), [])
        self.assertEqual(session.queries, [])


# One positive snippet per Dart rule
DART_POSITIVE = {
    'dart_bad_certificate_callback':
        'client.badCertificateCallback = (cert, host, port) => true;',
    'dart_http_overrides': 'HttpOverrides.global = MyOverrides();',
    'dart_webview_js_unrestricted':
        'c.setJavaScriptMode(JavaScriptMode.unrestricted);',
    'dart_webview_js_channel':
        "c.addJavaScriptChannel('Bridge', onMessageReceived: (m) {});",
    'dart_cleartext_url': "final u = Uri.parse('http://api.example.com/x');",
    'dart_prefs_sensitive': "await prefs.setString('auth_token', token);",
    'dart_insecure_random': 'final r = Random();',
    'dart_weak_hash': 'final d = md5.convert(bytes);',
    'dart_aes_ecb': 'final e = Encrypter(AES(key, mode: AESMode.ecb));',
    'dart_sql_interpolation':
        "db.rawQuery('SELECT * FROM users WHERE name = \"$name\"');",
    'dart_logging': "print('token: $token');",
    'dart_secure_random': 'final r = Random.secure();',
    'dart_ssl_pinning':
        'final ctx = SecurityContext(withTrustedRoots: false);\n'
        'ctx.setTrustedCertificatesBytes(certBytes);',
}
# Safe code that must not trigger the risky rules
DART_NEGATIVE = """
client.badCertificateCallback = (cert, host, port) => host == 'x';
c.setJavaScriptMode(JavaScriptMode.disabled);
final a = Uri.parse('https://api.example.com/x');
final b = Uri.parse('http://localhost:8080');
final e = Uri.parse('http://10.0.2.2:3000');
await prefs.setString('theme', 'dark');
final r = Random.secure();
final d = sha256.convert(bytes);
final enc = Encrypter(AES(key, mode: AESMode.gcm));
db.rawQuery('SELECT * FROM users WHERE name = ?', [name]);
// print('commented out');
"""
RISKY_RULES = set(DART_POSITIVE) - {'dart_secure_random', 'dart_ssl_pinning'}


class DartRulesTests(SimpleTestCase):

    def _scan(self, files):
        with tempfile.TemporaryDirectory() as tmp:
            for rel, code in files.items():
                path = Path(tmp) / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(code)
            return dart_code_analysis(tmp)

    def test_each_rule_fires(self):
        files = {f'lib/{rid}.dart': code
                 for rid, code in DART_POSITIVE.items()}
        res = self._scan(files)
        for rid in DART_POSITIVE:
            self.assertIn(rid, res, rid)
            # MobSF format: {relative path: 'line numbers'}
            paths = list(res[rid]['files'])
            self.assertTrue(any(p.endswith(f'{rid}.dart') for p in paths),
                            (rid, paths))

    def test_safe_code_quiet(self):
        res = self._scan({'lib/safe.dart': DART_NEGATIVE})
        self.assertFalse(set(res) & RISKY_RULES, set(res) & RISKY_RULES)

    def test_generated_and_build_dirs_ignored(self):
        code = DART_POSITIVE['dart_bad_certificate_callback']
        res = self._scan({'.dart_tool/x.dart': code, 'build/y.dart': code,
                          'lib/ok.dart': 'void main() {}'})
        self.assertNotIn('dart_bad_certificate_callback', res)

    def test_rule_metadata(self):
        rules = load_dart_rules()
        self.assertEqual({r['id'] for r in rules}, set(DART_POSITIVE))
        for rule in rules:
            self.assertIn(rule['severity'], ('high', 'warning', 'info',
                                             'good'))
            self.assertRegex(rule['metadata']['masvs'], r'^[a-z]+-\d+$')
            if rule['metadata']['cwe']:
                self.assertRegex(rule['metadata']['cwe'], r'^cwe-\d+$')


class BuildChecksTests(SimpleTestCase):

    def _sev(self, res):
        return {f['id']: f['severity'] for f in res}

    def test_debug_build(self):
        res = {f['id']: f for f in flutter_build_checks('debug', None, [])}
        self.assertEqual(res['flutter_debug_build']['severity'], 'high')
        self.assertEqual(res['flutter_debug_build']['cwe'], 'cwe-489')
        self.assertEqual(res['flutter_debug_build']['masvs'], 'code-2')

    def test_profile_build(self):
        self.assertEqual(self._sev(flutter_build_checks('profile', None, [])),
                         {'flutter_profile_build': 'warning'})

    def test_obfuscation(self):
        self.assertEqual(self._sev(flutter_build_checks('release', False, [])),
                         {'flutter_not_obfuscated': 'info'})
        self.assertEqual(self._sev(flutter_build_checks('release', True, [])),
                         {'flutter_obfuscated': 'good'})
        self.assertEqual(flutter_build_checks('release', None, []), [])

    def test_advisories(self):
        advisories = check_advisories('android', flutter=['3.44.9'])
        res = flutter_build_checks('release', None, advisories)
        self.assertEqual(self._sev(res),
                         {'flutter_advisory_GHSA-frr6-h895-5pxp': 'high'})
        self.assertEqual(res[0]['masvs'], 'code-5')
        self.assertEqual(res[0]['cwe'], 'cwe-295')

    def test_possibly_affected_is_one_level_lower(self):
        dart = ['3.13.%d' % i for i in range(8)]
        advisories = check_advisories('android', dart=dart)
        res = flutter_build_checks('release', None, advisories)
        self.assertEqual(self._sev(res),
                         {'flutter_advisory_GHSA-frr6-h895-5pxp': 'warning'})


def _libapp(features=b'product no-dwarf_stack_traces_mode arm64 android'):
    uris = b''.join(b'\x00' + u.encode() for u in _uris(40, ('flutter',
                                                             'webview_flutter')))
    return (_snapshot(snap_hash=SDK_3_12_HASH.encode(), features=features)
            + uris + b'\x00addJavaScriptChannel\x00')


ANDROID_APP = {
    'AndroidManifest.xml': b'<binary manifest>',
    'classes.dex': REG % (b'shared_preferences_android',
                          b'io.flutter.plugins.sharedpreferences.'
                          b'SharedPreferencesPlugin') + b'\x00',
    'lib/arm64-v8a/libflutter.so': ENGINE_3_44_9.encode() + b'\x00',
    'lib/arm64-v8a/libapp.so': _libapp(),
    'assets/flutter_assets/.env': b'API_KEY=abc123\n',
}


class BinaryAnalysisTests(SimpleTestCase):

    def _app(self, tmp, files):
        for rel, data in files.items():
            path = Path(tmp) / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return list(files)

    def test_android_app(self):
        manifest = parseString(MANIFEST.format(
            meta=DEEPLINK_META.format(value='true')))
        app = dict(ANDROID_APP)
        app['lib/arm64-v8a/libapp.so'] += (
            b'\x00plugins.flutter.io/shared_preferences\x00')
        with tempfile.TemporaryDirectory() as tmp:
            rels = self._app(tmp, app)
            res = flutter_binary_analysis(
                tmp, rels, 'android', parsed_manifest=manifest)
        self.assertTrue(res['is_flutter'])
        self.assertEqual(res['build_mode'], 'release')
        self.assertEqual(res['abis'], ['arm64-v8a'])
        self.assertEqual(
            [(c['kind'], c['name']) for c in res['platform_channels']],
            [('plugin', 'plugins.flutter.io/shared_preferences')])
        self.assertEqual(res['snapshot_hash'], SDK_3_12_HASH)
        # Engine names Flutter 3.44.9, which ships Dart 3.12.2
        self.assertEqual(res['dart'], ['3.12.2'])
        self.assertEqual(res['flutter'], ['3.44.9'])
        self.assertEqual(res['engine'], ENGINE_3_44_9)
        self.assertFalse(res['obfuscated'])
        self.assertFalse(res['split_debug_info'])
        self.assertEqual(res['packages'],
                         ['flutter', 'shared_preferences', 'webview_flutter'])
        self.assertEqual([p['name'] for p in res['plugins']],
                         ['shared_preferences_android'])
        self.assertEqual(res['assets'], [
            {'file': 'assets/flutter_assets/.env', 'type': 'env'}])
        self.assertEqual(res['asset_secrets'][0]['secrets'],
                         ['"API_KEY" : "abc123"'])
        self.assertEqual([a['id'] for a in res['advisories']],
                         ['GHSA-frr6-h895-5pxp'])
        ids = {f['id']: f['severity'] for f in res['findings']}
        self.assertEqual(ids['flutter_advisory_GHSA-frr6-h895-5pxp'], 'high')
        self.assertEqual(ids['flutter_insecure_storage'], 'warning')
        self.assertEqual(ids['flutter_deep_linking'], 'info')
        self.assertEqual(ids['flutter_js_channel'], 'info')
        self.assertEqual(ids['flutter_webview'], 'info')
        self.assertEqual(ids['flutter_not_obfuscated'], 'info')
        order = ['high', 'warning', 'info', 'good']
        sev = [order.index(f['severity']) for f in res['findings']]
        self.assertEqual(sev, sorted(sev))

    def test_ios_app_uses_plist_build_mode(self):
        files = {
            IOS_APP + 'Info.plist': plistlib.dumps(
                {'CFBundleExecutable': 'Runner',
                 'FlutterDeepLinkingEnabled': True}),
            IOS_APP + 'Runner': _swift_class(
                'webview_flutter_wkwebview', 'WebViewFlutterPlugin'),
            IOS_FW + 'Flutter': b'\xcf\xfa\xed\xfe',
            IOS_FW + 'Info.plist': _framework_plist(BuildMode='profile'),
            IOS_APP + 'Frameworks/App.framework/App': _libapp(
                b'product no-dwarf_stack_traces_mode arm64 ios'),
        }
        with tempfile.TemporaryDirectory() as tmp:
            rels = self._app(tmp, files)
            info = plistlib.loads(files[IOS_APP + 'Info.plist'])
            res = flutter_binary_analysis(tmp, rels, 'ios', info_plist=info)
        self.assertEqual(res['build_mode'], 'profile')
        self.assertEqual(res['flutter'], ['3.44.9'])
        # The TLS advisory is Android only
        self.assertEqual(res['advisories'], [])
        ids = {f['id'] for f in res['findings']}
        self.assertIn('flutter_profile_build', ids)
        self.assertIn('flutter_deep_linking', ids)
        self.assertIn('webview_flutter', res['packages'])

    def test_not_flutter(self):
        with tempfile.TemporaryDirectory() as tmp:
            rels = self._app(tmp, {'classes.dex': b'dex',
                                   'lib/arm64-v8a/libfoo.so': b'x'})
            self.assertEqual(flutter_binary_analysis(tmp, rels, 'android'),
                             {'is_flutter': False})

    def test_debug_build_without_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            rels = self._app(tmp, {
                'lib/x86_64/libflutter.so': ENGINE_3_44_9.encode() + b'\x00',
                'assets/flutter_assets/kernel_blob.bin': b'kernel'})
            res = flutter_binary_analysis(tmp, rels, 'android')
        self.assertEqual(res['build_mode'], 'debug')
        self.assertIsNone(res['snapshot_hash'])
        self.assertEqual(res['flutter'], ['3.44.9'])
        ids = {f['id']: f['severity'] for f in res['findings']}
        self.assertEqual(ids['flutter_debug_build'], 'high')


class AppPackagesTests(SimpleTestCase):

    def test_normalized_inventory(self):
        self.assertEqual(app_packages([
            'shared_preferences', 'shared_preferences_android',
            'shared_preferences_platform_interface',
            'webview_flutter_wkwebview', 'plugin_platform_interface',
            'flutter', 'http']),
            ['flutter', 'http', 'shared_preferences', 'webview_flutter'])

    def test_mobile_drops_desktop_helpers(self):
        # Desktop plugin code is compiled in but never runs on a phone
        self.assertEqual(mobile_packages([
            'path_provider', 'path_provider_windows', 'win32',
            'win32_registry', 'xdg_directories', 'ffi', 'path']),
            ['ffi', 'path', 'path_provider'])


PROJECT_PUBSPEC = """name: demo
dependencies:
  flutter:
    sdk: flutter
flutter:
  assets:
    - .env
    - assets/
    - ../../etc/passwd
"""
PROJECT_LOCK = """packages:
  shared_preferences:
    dependency: "direct main"
    source: hosted
    version: "2.5.6"
  http:
    dependency: "direct main"
    source: hosted
    version: "0.12.0"
"""
PROJECT_FILES = {
    'pubspec.yaml': PROJECT_PUBSPEC,
    'pubspec.lock': PROJECT_LOCK,
    '.env': 'API_KEY=abc123\n',
    'assets/config.json': '{"apiKey": "AIzaFAKE"}',
    'assets/logo.png': 'png',
    'assets/nested/secrets.json': '{"token": "deep"}',
    'lib/main.dart': DART_POSITIVE['dart_bad_certificate_callback'],
    'android/app/src/main/AndroidManifest.xml': MANIFEST.format(
        meta=DEEPLINK_META.format(value='true')),
    'ios/Runner/Info.plist': plistlib.dumps(
        {'FlutterDeepLinkingEnabled': False}).decode(),
}


class ClassifyAssetsTests(SimpleTestCase):

    def test_classify_outside_flutter_assets(self):
        self.assertEqual(classify_assets(['.env', 'assets/config.json',
                                          'assets/logo.png']), [
            {'file': '.env', 'type': 'env'},
            {'file': 'assets/config.json', 'type': 'config'}])


class SourceAnalysisTests(SimpleTestCase):

    def _project(self, tmp, files):
        for rel, data in files.items():
            path = Path(tmp) / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data)

    def test_project_without_osv(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._project(tmp, dict(PROJECT_FILES, **{
                'lib/battery.dart':
                    "const c = MethodChannel('samples.flutter.dev/battery');"}))
            res = flutter_source_analysis(tmp)
        self.assertTrue(res['is_flutter'])
        self.assertEqual([p['name'] for p in res['packages']],
                         ['http', 'shared_preferences'])
        self.assertEqual(
            [(c['name'], c['files']) for c in res['platform_channels']],
            [('samples.flutter.dev/battery', ['lib/battery.dart'])])
        self.assertIsNone(res['osv'])
        self.assertEqual(res['deep_linking'], {'android': True, 'ios': False})
        self.assertIn('dart_bad_certificate_callback', res['code_analysis'])
        # Declared assets only: dir entries are not recursive, traversal
        # entries are dropped
        self.assertEqual(res['assets'], [
            {'file': '.env', 'type': 'env'},
            {'file': 'assets/config.json', 'type': 'config'}])
        secrets = {s['file']: s['secrets'] for s in res['asset_secrets']}
        self.assertEqual(secrets['.env'], ['"API_KEY" : "abc123"'])
        ids = {f['id']: f['severity'] for f in res['findings']}
        self.assertEqual(ids['flutter_insecure_storage'], 'warning')
        self.assertEqual(ids['flutter_deep_linking'], 'info')
        self.assertFalse(any(i.startswith('flutter_osv_') for i in ids))

    def test_project_with_osv(self):
        session = _FakeSession(
            {'results': [{'vulns': [{'id': HTTP_GHSA}]}, {}]},
            {HTTP_GHSA: OSV_HTTP_VULN})
        with tempfile.TemporaryDirectory() as tmp:
            self._project(tmp, PROJECT_FILES)
            res = flutter_source_analysis(tmp, osv_enabled=True,
                                          osv_session=session)
        self.assertEqual(res['osv'][0]['name'], 'http')
        finding = [f for f in res['findings']
                   if f['id'] == 'flutter_osv_http'][0]
        self.assertEqual(finding['severity'], 'warning')
        self.assertEqual(finding['cwe'], 'cwe-74')
        self.assertEqual(finding['masvs'], 'code-5')
        self.assertEqual(finding['packages'], ['http'])

    def test_not_flutter_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._project(tmp, {'app/src/main/AndroidManifest.xml': 'x'})
            self.assertEqual(flutter_source_analysis(tmp),
                             {'is_flutter': False})


TEST_MD5 = 'f1a7f1a7f1a7f1a7f1a7f1a7f1a7f1a7'


class IntegrationTests(SimpleTestCase):

    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        # utils reads the settings module directly, so override_settings
        # does not reach scan_state_root(); patch it instead
        self.patch = mock.patch(
            'mobsf.MobSF.utils.scan_state_root',
            return_value=Path(self.home.name) / 'scan_state')
        self.patch.start()
        # The fake scan hash has no database row
        self.status = mock.patch(
            'mobsf.StaticAnalyzer.views.flutter.integration.'
            'append_scan_status')
        self.status.start()
        # Never touch the real MobSF home from tests
        self.assertTrue(str(scan_state_file(TEST_MD5, 'flutter.json'))
                        .startswith(self.home.name))

    def tearDown(self):
        self.status.stop()
        self.patch.stop()
        self.home.cleanup()

    def _app(self, tmp, files):
        for rel, data in files.items():
            path = Path(tmp) / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data if isinstance(data, bytes)
                             else data.encode())

    def test_save_and_load(self):
        save_result(TEST_MD5, {'is_flutter': True, 'findings': []})
        self.assertEqual(load_result(TEST_MD5),
                         {'is_flutter': True, 'findings': []})

    def test_load_missing_or_invalid(self):
        self.assertIsNone(load_result(TEST_MD5))
        self.assertIsNone(load_result('../../etc/passwd'))
        path = scan_state_file(TEST_MD5, 'flutter.json')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{not json')
        self.assertIsNone(load_result(TEST_MD5))
        path.write_text('["not", "a", "dict"]')
        self.assertIsNone(load_result(TEST_MD5))

    def test_symlinked_state_file_ignored(self):
        target = Path(self.home.name) / 'elsewhere.json'
        target.write_text('{"is_flutter": true}')
        path = scan_state_file(TEST_MD5, 'flutter.json')
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.symlink(target, path)
        except (OSError, NotImplementedError):
            self.skipTest('symlinks not supported')
        self.assertIsNone(load_result(TEST_MD5))

    def test_scan_binary_saves_flutter_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._app(tmp, ANDROID_APP)
            res = scan_binary(TEST_MD5, tmp, 'android')
        self.assertTrue(res['is_flutter'])
        self.assertEqual(load_result(TEST_MD5)['flutter'], ['3.44.9'])

    def test_scan_binary_non_flutter_saves_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._app(tmp, {'classes.dex': b'dex'})
            res = scan_binary(TEST_MD5, tmp, 'android')
        self.assertFalse(res['is_flutter'])
        self.assertIsNone(load_result(TEST_MD5))

    def test_scan_binary_ios_reads_info_plist(self):
        files = {
            IOS_APP + 'Info.plist': plistlib.dumps(
                {'CFBundleExecutable': 'Runner',
                 'FlutterDeepLinkingEnabled': True}),
            IOS_FW + 'Flutter': b'\xcf\xfa\xed\xfe',
            IOS_FW + 'Info.plist': _framework_plist(),
            IOS_APP + 'Frameworks/App.framework/App': _libapp(
                b'product no-dwarf_stack_traces_mode arm64 ios'),
        }
        with tempfile.TemporaryDirectory() as tmp:
            self._app(tmp, files)
            res = scan_binary(TEST_MD5, tmp, 'ios')
        self.assertTrue(res['deep_linking'])

    def test_scan_source_respects_osv_setting(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._app(tmp, PROJECT_FILES)
            with override_settings(FLUTTER_OSV_ENABLED=False):
                res = scan_source(TEST_MD5, tmp)
        self.assertIsNone(res['osv'])
        self.assertEqual(res['project_root'], '.')
        self.assertTrue(load_result(TEST_MD5)['is_flutter'])

    def test_invalid_hash_returns_none_quietly(self):
        with self.assertNoLogs('mobsf.StaticAnalyzer.views.flutter',
                               level='ERROR'):
            self.assertIsNone(
                scan_binary('not-an-md5', '/nonexistent', 'android'))
            self.assertIsNone(scan_source('not-an-md5', '/nonexistent'))

    def test_missing_ios_executable_is_quiet(self):
        files = {IOS_APP + 'Info.plist': plistlib.dumps(
            {'CFBundleExecutable': 'Runner'})}
        with tempfile.TemporaryDirectory() as tmp:
            self._app(tmp, files)
            with self.assertNoLogs('mobsf.StaticAnalyzer.views.flutter',
                                   level='ERROR'):
                self.assertEqual(flutter_plugins(tmp, list(files)), [])


FLUTTER_ZIP_TREE = {
    'pubspec.yaml': PUBSPEC,
    '.gitignore': 'flutter-ignore\n',
    'lib/main.dart': 'void main() {}',
    'android/.gitignore': 'android-ignore\n',
    'android/build.gradle.kts': '',
    'android/app/src/main/AndroidManifest.xml': MANIFEST.format(meta=''),
    'android/app/src/main/kotlin/com/example/MainActivity.kt': '',
    'ios/Runner/Info.plist': '',
}


class FlutterZipSourceTypeTests(SimpleTestCase):
    """MobSF's source check must accept Flutter project ZIPs."""

    def _tree(self, base, files):
        for rel, data in files.items():
            path = Path(base) / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data)

    def _check(self, app_dir):
        with mock.patch(
                'mobsf.StaticAnalyzer.views.android.apk.append_scan_status'):
            return valid_source_code(TEST_MD5, app_dir)

    def test_project_at_zip_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._tree(tmp, FLUTTER_ZIP_TREE)
            self.assertEqual(self._check(tmp), ('studio', True))
            root = Path(tmp)
            self.assertTrue(
                (root / 'app/src/main/AndroidManifest.xml').is_file())
            # Existing project files are kept, not overwritten
            self.assertEqual((root / '.gitignore').read_text(),
                             'flutter-ignore\n')
            self.assertTrue((root / 'lib/main.dart').is_file())
            self.assertFalse((root / 'android').exists())

    def test_project_wrapped_in_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._tree(Path(tmp) / 'demo', FLUTTER_ZIP_TREE)
            self.assertEqual(self._check(tmp), ('studio', True))
            self.assertTrue(
                (Path(tmp) / 'app/src/main/AndroidManifest.xml').is_file())

    def test_flutter_project_without_android_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._tree(tmp, {'pubspec.yaml': PUBSPEC, 'lib/main.dart': ''})
            self.assertEqual(self._check(tmp), ('', False))

    def test_plain_android_project_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._tree(tmp, {
                'app/src/main/AndroidManifest.xml': MANIFEST.format(meta=''),
                'app/src/main/java/A.java': ''})
            self.assertEqual(self._check(tmp), ('studio', True))


SARIF_RESULT = {
    'is_flutter': True,
    'project_root': 'demo',
    'findings': [
        {'id': 'flutter_debug_build', 'severity': 'high',
         'title': 'Flutter debug build', 'description': 'Debug build.',
         'packages': [], 'cwe': 'cwe-489', 'masvs': 'code-2'},
        {'id': 'flutter_webview', 'severity': 'info',
         'title': 'WebView', 'description': 'WebView.',
         'packages': ['webview_flutter'], 'cwe': 'cwe-749',
         'masvs': 'platform-7'},
        {'id': 'flutter_secure_storage', 'severity': 'good',
         'title': 'Encrypted storage', 'description': 'Good.',
         'packages': [], 'cwe': '', 'masvs': 'storage-1'},
    ],
    'code_analysis': {
        'dart_bad_certificate_callback': {
            'files': {'lib/main.dart': '9', 'lib/net.dart': '3,4'},
            'metadata': {'description': 'Accepts any cert.',
                         'severity': 'high', 'cwe': 'CWE-295: Improper',
                         'masvs': 'MSTG-NETWORK-3'}},
    },
    'asset_secrets': [
        {'file': '.env', 'secrets': ['"API_KEY" : "abc123secret"',
                                     f'GitHub token: {FAKE_GH_TOKEN}']}],
}


class SarifTests(SimpleTestCase):

    def test_structure(self):
        sarif = to_sarif(SARIF_RESULT)
        self.assertEqual(sarif['version'], '2.1.0')
        self.assertIn('sarif-schema-2.1.0', sarif['$schema'])
        driver = sarif['runs'][0]['tool']['driver']
        self.assertEqual(driver['name'], 'MobSF Flutter')
        rule_ids = {r['id'] for r in driver['rules']}
        self.assertEqual(rule_ids, {
            'flutter_debug_build', 'flutter_webview',
            'dart_bad_certificate_callback', 'flutter_asset_secret'})

    def test_levels_and_good_excluded(self):
        results = to_sarif(SARIF_RESULT)['runs'][0]['results']
        levels = {r['ruleId']: r['level'] for r in results}
        self.assertEqual(levels['flutter_debug_build'], 'error')
        self.assertEqual(levels['flutter_webview'], 'note')
        self.assertNotIn('flutter_secure_storage', levels)

    def test_rule_metadata(self):
        rules = {r['id']: r for r in
                 to_sarif(SARIF_RESULT)['runs'][0]['tool']['driver']['rules']}
        rule = rules['flutter_debug_build']
        self.assertEqual(rule['properties']['security-severity'], '8.0')
        self.assertIn('CWE-489', rule['properties']['tags'])
        self.assertIn('MASVS-CODE-2', rule['properties']['tags'])

    def test_dart_locations_one_per_line(self):
        results = [r for r in to_sarif(SARIF_RESULT)['runs'][0]['results']
                   if r['ruleId'] == 'dart_bad_certificate_callback']
        locs = sorted(
            (loc['physicalLocation']['artifactLocation']['uri'],
             loc['physicalLocation']['region']['startLine'])
            for r in results for loc in r['locations'])
        self.assertEqual(locs, [('demo/lib/main.dart', 9),
                                ('demo/lib/net.dart', 3),
                                ('demo/lib/net.dart', 4)])

    def test_secrets_redacted(self):
        text = json.dumps(to_sarif(SARIF_RESULT))
        self.assertNotIn('abc123secret', text)
        self.assertNotIn(FAKE_GH_TOKEN, text)
        # Key names stay visible (quotes are JSON-escaped in the dump)
        self.assertIn('API_KEY', text)
        secret = [r for r in to_sarif(SARIF_RESULT)['runs'][0]['results']
                  if r['ruleId'] == 'flutter_asset_secret'][0]
        self.assertEqual(
            secret['locations'][0]['physicalLocation']['artifactLocation']
            ['uri'], 'demo/.env')

    def test_redact(self):
        self.assertEqual(redact_secret('"API_KEY" : "abc123secret"'),
                         '"API_KEY" : "abc1****"')
        self.assertEqual(redact_secret(f'GitHub token: {FAKE_GH_TOKEN}'),
                         'GitHub token: ghp_****')
        self.assertEqual(redact_secret('short'), '****')

    def test_non_flutter(self):
        sarif = to_sarif({'is_flutter': False})
        self.assertEqual(sarif['runs'][0]['results'], [])


class CLITests(SimpleTestCase):

    def _zip(self, tmp, files, name):
        path = Path(tmp) / name
        with zipfile.ZipFile(path, 'w') as zf:
            for rel, data in files.items():
                zf.writestr(rel, data)
        return path

    def test_scan_apk_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = self._zip(tmp, ANDROID_APP, 'app.apk')
            res = scan_path(apk)
        self.assertTrue(res['is_flutter'])
        self.assertEqual(res['platform'], 'android')
        self.assertEqual(res['flutter'], ['3.44.9'])

    def test_scan_project_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            for rel, data in PROJECT_FILES.items():
                path = Path(tmp) / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(data)
            res = scan_path(tmp)
        self.assertEqual(res['project_root'], '.')
        self.assertIsNone(res['osv'])

    def test_scan_ipa_detects_ios(self):
        files = {
            IOS_APP + 'Info.plist': plistlib.dumps(
                {'CFBundleExecutable': 'Runner'}),
            IOS_FW + 'Flutter': b'\xcf\xfa\xed\xfe',
            IOS_FW + 'Info.plist': _framework_plist(),
            IOS_APP + 'Frameworks/App.framework/App': _libapp(),
        }
        with tempfile.TemporaryDirectory() as tmp:
            res = scan_path(self._zip(tmp, files, 'app.ipa'))
        self.assertEqual(res['platform'], 'ios')

    def test_zip_slip_member_not_extracted(self):
        files = dict(ANDROID_APP)
        files['../../evil.txt'] = b'x'
        with tempfile.TemporaryDirectory() as tmp:
            apk = self._zip(tmp, files, 'app.apk')
            res = scan_path(apk)
            self.assertFalse((Path(tmp).parent / 'evil.txt').exists())
        self.assertTrue(res['is_flutter'])

    def test_missing_path(self):
        with self.assertRaises(FileNotFoundError):
            scan_path('/nonexistent/app.apk')

    def test_command_json_sarif_and_fail_on(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = self._zip(tmp, ANDROID_APP, 'app.apk')
            out = Path(tmp) / 'out.sarif'
            call_command('flutter_scan', str(apk), '--format', 'sarif',
                         '--output', str(out))
            sarif = json.loads(out.read_text())
            self.assertEqual(sarif['version'], '2.1.0')
            self.assertTrue(sarif['runs'][0]['results'])
            buf = io.StringIO()
            call_command('flutter_scan', str(apk), stdout=buf)
            self.assertTrue(json.loads(buf.getvalue())['is_flutter'])
            # The sample has a high advisory finding
            with self.assertRaises(SystemExit) as ctx:
                call_command('flutter_scan', str(apk), '--fail-on', 'high',
                             stdout=io.StringIO())
            self.assertEqual(ctx.exception.code, 1)


class CLIStdoutTests(SimpleTestCase):

    def test_stdout_is_clean_json_without_api_key(self):
        manage = Path(settings.BASE_DIR).parent / 'manage.py'
        with tempfile.TemporaryDirectory() as tmp:
            apk = CLITests()._zip(tmp, ANDROID_APP, 'app.apk')
            proc = subprocess.run(
                [sys.executable, str(manage), 'flutter_scan', str(apk)],
                capture_output=True, text=True, timeout=300,
                env={**os.environ, 'MOBSF_DISABLE_AUTHENTICATION': '1'})
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        self.assertNotIn('REST API Key', proc.stdout)
        self.assertTrue(json.loads(proc.stdout)['is_flutter'])


class MobSFOutputSkipTests(SimpleTestCase):
    """MobSF writes apktool and decompiler output into the scan folder."""

    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.patch = mock.patch(
            'mobsf.MobSF.utils.scan_state_root',
            return_value=Path(self.home.name) / 'scan_state')
        self.patch.start()
        self.status = mock.patch(
            'mobsf.StaticAnalyzer.views.flutter.integration.'
            'append_scan_status')
        self.status.start()

    def tearDown(self):
        self.status.stop()
        self.patch.stop()
        self.home.cleanup()

    def test_apktool_and_decompiler_output_skipped(self):
        files = dict(ANDROID_APP)
        # apktool's copy of the APK and leftovers of an earlier scan
        for rel, data in ANDROID_APP.items():
            files[f'apktool_out/{rel}'] = data
        files['java_source/com/example/A.java'] = b'class A {}'
        files['smali_source/com/example/A.smali'] = b'.class A'
        with tempfile.TemporaryDirectory() as tmp:
            for rel, data in files.items():
                path = Path(tmp) / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            res = scan_binary(TEST_MD5, tmp, 'android')
        self.assertEqual(res['engine_files'], ['lib/arm64-v8a/libflutter.so'])
        self.assertEqual(res['snapshots'], ['lib/arm64-v8a/libapp.so'])
        self.assertEqual(res['assets'], [
            {'file': 'assets/flutter_assets/.env', 'type': 'env'}])
        self.assertEqual([s['file'] for s in res['asset_secrets']],
                         ['assets/flutter_assets/.env'])


class CLIDatabaseTests(SimpleTestCase):

    def test_cli_scan_quiet_without_scan_database(self):
        # CLI scans have no scan record; an unmigrated database must not
        # produce error logs from unzip()'s scan status updates
        with tempfile.TemporaryDirectory() as tmp:
            apk = CLITests()._zip(tmp, ANDROID_APP, 'app.apk')
            with mock.patch(
                    'mobsf.MobSF.utils.RecentScansDB.objects.only',
                    side_effect=OperationalError('no such table')), \
                    self.assertNoLogs('mobsf.MobSF.utils', level='ERROR'):
                res = scan_path(apk)
        self.assertTrue(res['is_flutter'])


DART_CHANNELS = (
    b'\x00plugins.flutter.io/shared_preferences\x00'
    b'\x00plugins.flutter.io/webview\x00'
    b'\x00plugins.it_nomads.com/flutter_secure_storage\x00'
    b'\x00samples.flutter.dev/battery\x00'
    # Text shaped like a channel, absent from the native code
    b'\x00api.example.com/users\x00'
    # Flutter engine channels
    b'\x00dev.flutter/channel-buffers\x00\x00flutter/platform\x00'
    b'\x00dev.flutter.pigeon.webview_flutter_android.WebView.loadUrl\x00'
    b'\x00dev.flutter.pigeon.webview_flutter_android.WebView.reload\x00'
    # Old Pigeon names carry no package
    b'\x00dev.flutter.pigeon.WKWebViewHostApi.create\x00')
PACKAGES = ['flutter', 'flutter_secure_storage', 'shared_preferences',
            'webview_flutter']


class PlatformChannelTests(SimpleTestCase):

    def _app(self, tmp, files):
        for rel, data in files.items():
            path = Path(tmp) / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return list(files)

    def _rows(self, res):
        return [(c['kind'], c['name'], c['package'], c['count'])
                for c in res]

    def test_android_attribution(self):
        with tempfile.TemporaryDirectory() as tmp:
            rels = self._app(tmp, {
                'lib/arm64-v8a/libapp.so': DART_CHANNELS,
                # dex strings follow a length byte
                'classes.dex': b'dex\n035\x00\x1bsamples.flutter.dev/battery\x00',
            })
            res = binary_channels(
                tmp, rels, Path(tmp) / 'lib/arm64-v8a/libapp.so', PACKAGES)
        self.assertEqual(self._rows(res), [
            ('app', 'samples.flutter.dev/battery', None, 1),
            ('pigeon', 'dev.flutter.pigeon.webview_flutter_android.*',
             'webview_flutter', 2),
            ('plugin', 'plugins.flutter.io/shared_preferences',
             'shared_preferences', 1),
            ('plugin', 'plugins.flutter.io/webview', 'webview_flutter', 1),
            ('plugin', 'plugins.it_nomads.com/flutter_secure_storage',
             'flutter_secure_storage', 1),
        ])

    def test_dex_length_byte_may_be_a_letter(self):
        # 48 characters: the dex length byte is '0'
        name = b'com.example.app/' + b'b' * 32
        with tempfile.TemporaryDirectory() as tmp:
            rels = self._app(tmp, {
                'lib/arm64-v8a/libapp.so': b'\x00' + name + b'\x00',
                'classes2.dex': b'\x00' + bytes([len(name)]) + name + b'\x00',
            })
            res = binary_channels(
                tmp, rels, Path(tmp) / 'lib/arm64-v8a/libapp.so', PACKAGES)
        self.assertEqual(self._rows(res), [('app', name.decode(), None, 1)])

    def test_dart_name_followed_by_other_data(self):
        # Dart strings are not terminated; the next byte may be a letter
        with tempfile.TemporaryDirectory() as tmp:
            rels = self._app(tmp, {
                'lib/arm64-v8a/libapp.so': (
                    b'\x00samples.flutter.dev/batteryX'
                    b'\x00plugins.flutter.io/shared_preferencesX'),
                'classes.dex': (
                    b'\x00\x1bsamples.flutter.dev/battery\x00'
                    b'\x00\x25plugins.flutter.io/shared_preferences\x00'),
            })
            res = binary_channels(
                tmp, rels, Path(tmp) / 'lib/arm64-v8a/libapp.so', PACKAGES)
        self.assertEqual(self._rows(res), [
            ('app', 'samples.flutter.dev/battery', None, 1),
            ('plugin', 'plugins.flutter.io/shared_preferences',
             'shared_preferences', 1)])

    def test_dex_wrong_length_byte_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            rels = self._app(tmp, {
                'lib/arm64-v8a/libapp.so': DART_CHANNELS,
                'classes.dex': b'\x00\x05samples.flutter.dev/battery\x00',
            })
            res = binary_channels(
                tmp, rels, Path(tmp) / 'lib/arm64-v8a/libapp.so', PACKAGES)
        self.assertEqual([c for c in res if c['kind'] == 'app'], [])

    def test_native_longer_name_does_not_confirm(self):
        with tempfile.TemporaryDirectory() as tmp:
            rels = self._app(tmp, {
                'lib/arm64-v8a/libapp.so': DART_CHANNELS,
                'classes.dex': b'\x00\x1csamples.flutter.dev/battery2\x00',
            })
            res = binary_channels(
                tmp, rels, Path(tmp) / 'lib/arm64-v8a/libapp.so', PACKAGES)
        self.assertEqual([c for c in res if c['kind'] == 'app'], [])

    def test_ios_main_executable_confirms(self):
        app = 'Payload/Runner.app/'
        with tempfile.TemporaryDirectory() as tmp:
            rels = self._app(tmp, {
                app + 'Frameworks/App.framework/App': DART_CHANNELS,
                app + 'Info.plist': plistlib.dumps(
                    {'CFBundleExecutable': 'Runner'}),
                app + 'Runner': b'\x00samples.flutter.dev/battery\x00',
            })
            res = binary_channels(
                tmp, rels, Path(tmp) / (app + 'Frameworks/App.framework/App'),
                PACKAGES)
        self.assertIn(('app', 'samples.flutter.dev/battery', None, 1),
                      self._rows(res))

    def test_plugin_needs_detected_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            rels = self._app(tmp, {'lib/arm64-v8a/libapp.so': DART_CHANNELS})
            res = binary_channels(
                tmp, rels, Path(tmp) / 'lib/arm64-v8a/libapp.so', ['flutter'])
        # 'flutter' alone matches no channel; nothing confirmed natively
        self.assertEqual(self._rows(res), [
            ('pigeon', 'dev.flutter.pigeon.webview_flutter_android.*',
             'webview_flutter', 2)])

    def test_no_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(binary_channels(tmp, [], None, PACKAGES), [])
            self.assertEqual(binary_channels(
                tmp, [], Path(tmp) / 'missing.so', PACKAGES), [])

    def test_source_channels(self):
        with tempfile.TemporaryDirectory() as tmp, \
                tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            self._app(tmp, {
                'lib/main.dart': (
                    b"const c = MethodChannel('samples.flutter.dev/battery');\n"
                    b'final e = EventChannel("app.events/stream");\n'
                    b'const m = BasicMessageChannel<String>(\n'
                    b"    'app/messages', StringCodec());\n"
                    b"final o = OptionalMethodChannel('x.y/z');\n"
                    b"final d = MethodChannel('dynamic/$name');\n"),
                'lib/src/again.dart':
                    b"MethodChannel('samples.flutter.dev/battery')",
                'build/generated.dart': b"MethodChannel('ignored.build/x')",
            })
            evil = Path(outside) / 'evil.dart'
            evil.write_text("MethodChannel('evil.link/x')")
            (root / 'lib' / 'link.dart').symlink_to(evil)
            res = source_channels(root)
        self.assertEqual(
            [(c['kind'], c['name'], c['files']) for c in res], [
                ('app', 'app.events/stream', ['lib/main.dart']),
                ('app', 'app/messages', ['lib/main.dart']),
                ('app', 'samples.flutter.dev/battery',
                 ['lib/main.dart', 'lib/src/again.dart']),
                ('app', 'x.y/z', ['lib/main.dart']),
            ])


class ChannelTemplateTests(SimpleTestCase):

    def test_channels_rendered_escaped(self):
        flutter = {'is_flutter': True, 'project_root': '.', 'packages': [],
                   'deep_linking': {'android': False, 'ios': False},
                   'osv': None, 'code_analysis': {}, 'assets': [],
                   'asset_secrets': [],
                   'findings': [], 'platform_channels': [
                       {'name': 'evil/<script>x</script>', 'kind': 'app',
                        'package': None, 'count': 1,
                        'files': ['lib/<b>.dart'],
                        'native_files': ['ios/Runner/<i>.swift']},
                       {'name': 'dev.flutter.pigeon.webview_flutter_android.*',
                        'kind': 'pigeon', 'package': 'webview_flutter',
                        'count': 65, 'files': [], 'native_files': []}],
                   'ios_shell': None}
        for tpl in ('static_analysis/flutter/section.html',
                    'pdf/flutter/section.html'):
            html = render_to_string(tpl, {'flutter': flutter})
            self.assertIn('evil/&lt;script&gt;x&lt;/script&gt;', html)
            self.assertNotIn('<script>x', html)
            self.assertIn('Pigeon (65 channels)', html)
        web = render_to_string(
            'static_analysis/flutter/section.html', {'flutter': flutter})
        self.assertIn('lib/&lt;b&gt;.dart', web)
        self.assertIn('ios/Runner/&lt;i&gt;.swift', web)

    def test_ios_shell_rendered_escaped(self):
        flutter = {
            'is_flutter': True, 'project_root': '.', 'packages': [],
            'deep_linking': {'android': False, 'ios': False},
            'osv': None, 'code_analysis': {}, 'assets': [],
            'asset_secrets': [], 'findings': [], 'platform_channels': [],
            'ios_shell': {
                'code_analysis': {'ios_file_no_special': {
                    'files': {'Runner/<a>.swift': '1'},
                    'metadata': {'description': 'No protection <x>',
                                 'severity': 'high',
                                 'cwe': 'CWE-311: Missing',
                                 'masvs': 'MSTG-STORAGE-1'}}},
                'permissions': {'NSCameraUsageDescription': {
                    'info': 'Camera', 'status': 'dangerous',
                    'description': '<img src=x>'}},
                'ats_findings': [{'issue': 'Arbitrary loads <y>',
                                  'severity': 'high',
                                  'description': 'Allowed'}],
                'url_schemes': ['demo<app>'],
            }}
        web = render_to_string(
            'static_analysis/flutter/section.html', {'flutter': flutter})
        self.assertIn('IOS APP (ios/)', web)
        for text in ('Runner/&lt;a&gt;.swift', 'No protection &lt;x&gt;',
                     '&lt;img src=x&gt;', 'Arbitrary loads &lt;y&gt;',
                     'demo&lt;app&gt;', 'NSCameraUsageDescription'):
            self.assertIn(text, web)
        self.assertNotIn('<img src=x>', web)
        pdf = render_to_string(
            'pdf/flutter/section.html', {'flutter': flutter})
        self.assertIn('iOS app (ios/)', pdf)
        self.assertIn('Arbitrary loads &lt;y&gt;', pdf)
        self.assertIn('No protection &lt;x&gt;', pdf)


IOS_PLIST = plistlib.dumps({
    'CFBundleName': 'demo',
    'NSAppTransportSecurity': {'NSAllowsArbitraryLoads': True},
    'NSCameraUsageDescription': 'Scan codes',
    'CFBundleURLTypes': [{'CFBundleURLSchemes': ['demoapp']}],
})
UNPROTECTED = b'try data.write(to: url, options: .noFileProtection)\n'
PLUGIN_PLIST = plistlib.dumps({'NSMicrophoneUsageDescription': 'x'})


class IOSShellTests(SimpleTestCase):

    def _tree(self, tmp, files):
        for rel, data in files.items():
            path = Path(tmp) / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)

    def _project(self, tmp):
        self._tree(tmp, {
            'ios/Runner/Info.plist': IOS_PLIST,
            'ios/Runner/AppDelegate.swift': UNPROTECTED,
            # Not the app developer's code
            'ios/Pods/Lib/Lib.swift': UNPROTECTED,
            'ios/.symlinks/plugins/p/ios/Classes/P.swift': UNPROTECTED,
            'ios/.symlinks/plugins/p/ios/Info.plist': PLUGIN_PLIST,
            'ios/Flutter/Generated.swift': UNPROTECTED,
        })

    def test_shell_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._project(tmp)
            res = ios_shell_analysis(None, tmp)
        rule = res['code_analysis']['ios_file_no_special']
        self.assertEqual(list(rule['files']), ['Runner/AppDelegate.swift'])
        self.assertEqual(rule['metadata']['severity'], 'high')
        self.assertEqual(list(res['permissions']),
                         ['NSCameraUsageDescription'])
        self.assertIn('high', [a['severity'] for a in res['ats_findings']])
        self.assertEqual(res['url_schemes'], ['demoapp'])

    def test_raised_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._project(tmp)
            found = ios_shell_findings(ios_shell_analysis(None, tmp))
        ids = {f['id']: f for f in found}
        unprotected = ids['flutter_ios_ios_file_no_special']
        self.assertEqual(unprotected['severity'], 'high')
        self.assertTrue(unprotected['title'].startswith('iOS app: '))
        self.assertEqual(unprotected['cwe'], 'cwe-311')
        self.assertEqual(unprotected['masvs'], 'storage-1')
        ats = [f for f in found if f['id'].startswith('flutter_ios_ats_')]
        self.assertTrue(ats)
        self.assertTrue(all(f['severity'] in ('high', 'warning')
                            for f in found))
        self.assertEqual(ios_shell_findings(None), [])

    def test_no_ios_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(ios_shell_analysis(None, tmp))

    def test_ios_dir_symlink_ignored(self):
        with tempfile.TemporaryDirectory() as tmp, \
                tempfile.TemporaryDirectory() as outside:
            self._project(outside)
            (Path(tmp) / 'ios').symlink_to(Path(outside) / 'ios')
            self.assertIsNone(ios_shell_analysis(None, tmp))

    def test_source_analysis_includes_ios(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._tree(tmp, {k: v.encode() for k, v in PROJECT_FILES.items()})
            self._project(tmp)
            res = flutter_source_analysis(tmp)
        self.assertIn('ios_file_no_special',
                      res['ios_shell']['code_analysis'])
        ids = [f['id'] for f in res['findings']]
        self.assertIn('flutter_ios_ios_file_no_special', ids)
        order = ['high', 'warning', 'info', 'good']
        sev = [order.index(f['severity']) for f in res['findings']]
        self.assertEqual(sev, sorted(sev))

    def test_channel_native_files(self):
        name = b'samples.flutter.dev/battery'
        with tempfile.TemporaryDirectory() as tmp:
            self._tree(tmp, {
                'lib/main.dart': b"MethodChannel('" + name + b"')",
                'android/app/src/main/kotlin/com/example/demo/'
                'MainActivity.kt': b'private val channel = "' + name + b'"',
                'ios/Runner/AppDelegate.swift':
                    b'FlutterMethodChannel(name: "' + name + b'",',
                # Plugin and build copies are not the app's handler
                'ios/.symlinks/plugins/p/ios/P.swift': b'"' + name + b'"',
                'android/app/build/tmp/X.java': b'"' + name + b'"',
                # Longer name is a different channel
                'ios/Runner/Other.swift': b'"' + name + b'2"',
            })
            res = source_channels(tmp)
        self.assertEqual(res[0]['native_files'], [
            'android/app/src/main/kotlin/com/example/demo/MainActivity.kt',
            'ios/Runner/AppDelegate.swift'])


SCORE_RESULT = {'is_flutter': True, 'findings': [
    {'id': 'flutter_debug_build', 'severity': 'high',
     'title': 'Debug build', 'description': 'Ships kernel_blob.bin'},
    {'id': 'flutter_ios_ats_x', 'severity': 'warning',
     'title': 'iOS app: ATS exception', 'description': 'd'},
    {'id': 'flutter_no_ssl_pinning', 'severity': 'info',
     'title': 'No SSL pinning', 'description': 'd'},
    {'id': 'flutter_obfuscated', 'severity': 'good',
     'title': 'Obfuscated', 'description': 'd'},
]}


class AppSecScoreTests(SimpleTestCase):

    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.patch = mock.patch(
            'mobsf.MobSF.utils.scan_state_root',
            return_value=Path(self.home.name) / 'scan_state')
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.home.cleanup()

    def _android(self):
        return {'md5': TEST_MD5, 'code_analysis': {'findings': {}},
                'permissions': {}, 'domains': {}, 'firebase_urls': [],
                'trackers': {}, 'secrets': [], 'certificate_analysis': {},
                'network_security': {}, 'manifest_analysis': {}}

    def test_appsec_findings(self):
        save_result(TEST_MD5, SCORE_RESULT)
        found = appsec_findings(TEST_MD5)
        self.assertEqual([(s, f['title'], f['section']) for s, f in found], [
            ('high', 'Debug build', 'flutter'),
            ('warning', 'iOS app: ATS exception', 'flutter'),
            ('info', 'No SSL pinning', 'flutter'),
            ('secure', 'Obfuscated', 'flutter')])

    def test_no_result_or_bad_hash(self):
        self.assertEqual(appsec_findings(TEST_MD5), [])
        self.assertEqual(appsec_findings('../etc'), [])
        self.assertEqual(appsec_findings(None), [])

    def test_score_counts_flutter(self):
        before = get_android_dashboard(self._android(), True)
        self.assertEqual(before['high'], [])
        save_result(TEST_MD5, SCORE_RESULT)
        after = get_android_dashboard(self._android(), True)
        self.assertEqual([f['title'] for f in after['high']],
                         ['Debug build'])
        self.assertEqual([f['section'] for f in after['warning']],
                         ['flutter'])
        self.assertIn('Obfuscated', [f['title'] for f in after['secure']])
        self.assertLess(after['security_score'], 100)
