"""Tests for Flutter project source detection (flutter_android_source)."""
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

from mobsf.StaticAnalyzer.views.android.apk import flutter_android_source

PUBSPEC = ('name: demo\n'
           'dependencies:\n'
           '  flutter:\n'
           '    sdk: flutter\n')
MANIFEST = '<manifest package="com.demo"/>'


def _flutter_project(root):
    """Create a minimal Flutter project rooted at root."""
    root.mkdir(parents=True, exist_ok=True)
    (root / 'pubspec.yaml').write_text(PUBSPEC)
    (root / 'lib').mkdir(exist_ok=True)
    (root / 'lib' / 'main.dart').write_text('void main() {}')
    man = root / 'android' / 'app' / 'src' / 'main' / 'AndroidManifest.xml'
    man.parent.mkdir(parents=True, exist_ok=True)
    man.write_text(MANIFEST)
    kt = root / 'android' / 'app' / 'src' / 'main' / 'kotlin' / 'Main.kt'
    kt.parent.mkdir(parents=True, exist_ok=True)
    kt.write_text('fun main() {}')


class FlutterAndroidSourceTests(SimpleTestCase):

    def test_project_at_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp)
            _flutter_project(app)
            # Detected in place; nothing is moved.
            self.assertEqual(flutter_android_source(app), app / 'android')
            self.assertTrue((app / 'lib' / 'main.dart').is_file())

    def test_project_one_level_down(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp)
            _flutter_project(app / 'demo')
            self.assertEqual(
                flutter_android_source(app), app / 'demo' / 'android')

    def test_wrapper_named_app(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp)
            _flutter_project(app / 'app')
            self.assertEqual(
                flutter_android_source(app), app / 'app' / 'android')

    def test_pure_dart_package_without_android(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp)
            app.mkdir(exist_ok=True)
            (app / 'pubspec.yaml').write_text(PUBSPEC)
            self.assertIsNone(flutter_android_source(app))

    def test_plain_dir_is_not_flutter(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(flutter_android_source(Path(tmp)))
