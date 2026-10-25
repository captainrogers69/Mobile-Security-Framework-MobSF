"""Unit tests for Flutter detection."""
import os
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

from mobsf.StaticAnalyzer.views.flutter.detect import (
    detect_flutter,
    flutter_from_dir,
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
