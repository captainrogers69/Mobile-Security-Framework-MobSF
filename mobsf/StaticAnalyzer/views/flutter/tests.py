"""Unit tests for Flutter detection."""
import os
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

from mobsf.StaticAnalyzer.views.flutter.detect import (
    detect_flutter,
    flutter_from_dir,
)
from mobsf.StaticAnalyzer.views.flutter.snapshot import (
    read_snapshot_header,
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
