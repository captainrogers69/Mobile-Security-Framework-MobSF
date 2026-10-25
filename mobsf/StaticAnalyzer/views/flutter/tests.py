"""Unit tests for Flutter detection."""
import os
import re
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

from mobsf.StaticAnalyzer.views.flutter.assets import (
    asset_secrets,
    audit_assets,
)
from mobsf.StaticAnalyzer.views.flutter.detect import (
    detect_flutter,
    flutter_from_dir,
)
from mobsf.StaticAnalyzer.views.flutter.snapshot import (
    read_snapshot_header,
)
from mobsf.StaticAnalyzer.views.flutter.versions import (
    dart_version,
    load_dart_versions,
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
