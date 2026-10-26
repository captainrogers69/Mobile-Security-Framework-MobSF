"""Unit tests for Flutter detection."""
import os
import plistlib
import random
import re
import tempfile
from pathlib import Path

from defusedxml.minidom import parseString

from django.test import SimpleTestCase

from mobsf.StaticAnalyzer.views.common.binary.elf import ELFChecksec
from mobsf.StaticAnalyzer.views.flutter.advisories import (
    check_advisories,
    load_advisories,
)
from mobsf.StaticAnalyzer.views.flutter.assets import (
    asset_secrets,
    audit_assets,
)
from mobsf.StaticAnalyzer.views.flutter.checks import (
    flutter_binary_checks,
    flutter_checks,
    load_check_packages,
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
from mobsf.StaticAnalyzer.views.flutter.obfuscation import (
    obfuscation_info,
    package_uris,
    split_debug_info,
)
from mobsf.StaticAnalyzer.views.flutter.plugins import (
    base_package,
    flutter_plugins,
)
from mobsf.StaticAnalyzer.views.flutter.symbols import uses_js_channels
from mobsf.StaticAnalyzer.views.flutter.source import (
    is_flutter_source,
    pubspec_lock_packages,
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
