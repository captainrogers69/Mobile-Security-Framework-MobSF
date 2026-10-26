# -*- coding: utf_8 -*-
"""Flutter platform channels used by an app (inventory, no findings).

Channel names are string literals, so they survive --obfuscate. In an
APK/IPA, a name is listed only when attributed:
- plugin: it names a detected package (plugins.flutter.io/webview)
- app: a string of the app's native code (classes*.dex, iOS main
  executable) that the Dart snapshot also contains: both ends of the
  channel
- pigeon: dev.flutter.pigeon.<package>.<Api>.<method>, one row per package
Other channel-shaped text (e.g. api.example.com/users) is dropped, and so
are the Flutter engine's own channels.

Native strings have exact bounds (dex: NUL, length byte, text, NUL;
Mach-O: C strings). Dart snapshot strings are not terminated, so there a
name is only required to start at a boundary.

For Flutter project ZIPs, names passed to MethodChannel, EventChannel and
BasicMessageChannel in the Dart sources are listed as app channels, with
the native files in android/ and ios/ that use the same name (the
handlers worth reviewing).
"""
import logging
import os
import re
from pathlib import Path, PurePosixPath

from mobsf.MobSF.security import is_pipe_or_link
from mobsf.StaticAnalyzer.views.flutter.dart_analysis import IGNORED_DIRS
from mobsf.StaticAnalyzer.views.flutter.fileio import (
    open_regular,
    safe_join,
    scan_regex,
)
from mobsf.StaticAnalyzer.views.flutter.plugins import (
    DEX_RE,
    base_package,
    ios_executable,
)

logger = logging.getLogger(__name__)

NAME = (rb'[a-z0-9][a-z0-9_-]{0,62}(?:\.[a-z0-9_-]{1,63}){1,8}'
        rb'(?:/[A-Za-z0-9_.-]{1,100}){1,6}')
NAME_START = rb'(?<![A-Za-z0-9_.$/-])'
CHANNEL_RE = re.compile(NAME_START + b'(' + NAME + rb')(?![A-Za-z0-9_.$/-])')
DEX_STRING_RE = re.compile(rb'(?<=\x00)([\x01-\x7f])(' + NAME + rb')(?=\x00)')
C_STRING_RE = re.compile(rb'(?<=\x00)(' + NAME + rb')(?=\x00)')
PIGEON_RE = re.compile(
    rb'(?<![A-Za-z0-9_.$/-])dev\.flutter\.pigeon\.([a-z][a-z0-9_]{0,63})'
    rb'\.[A-Z][A-Za-z0-9_]{0,100}(?:\.[A-Za-z0-9_$]{1,100}){1,3}'
    rb'(?![A-Za-z0-9_.$/-])')
ENGINE_PREFIXES = ('dev.flutter/',)
SOURCE_RE = re.compile(
    r'\b(?:Optional)?(?:MethodChannel|EventChannel|BasicMessageChannel)'
    r'\s*(?:<[^<>()]{0,200}(?:<[^<>()]{0,200}>[^<>()]{0,200})?>)?'
    r'\s*\(\s*([\'"])([^\'"$\\\r\n]{1,200})\1')
MAX_CANDIDATES = 500
MAX_NATIVE_FILES = 200
MAX_DART_FILES = 5000
MAX_DART_SIZE = 1024 * 1024
NATIVE_DIRS = ('android', 'ios')
NATIVE_EXTS = ('.kt', '.java', '.swift', '.m', '.mm')
# Build output, dependencies and plugin sources: not the app's handlers
NATIVE_SKIP = {'build', '.gradle', '.cxx', 'Pods', '.symlinks', 'Flutter',
               '.dart_tool'}


def _row(name, kind, package=None, count=1, files=None, native_files=None):
    return {'name': name, 'kind': kind, 'package': package,
            'count': count, 'files': sorted(files or []),
            'native_files': sorted(native_files or [])}


def _package_keys(packages):
    """Map name parts a plugin channel may use to the package name."""
    keys = {}
    for pkg in packages or []:
        if not isinstance(pkg, str):
            continue
        base = base_package(pkg)
        for key in (base, base.removesuffix('_flutter'),
                    base.removeprefix('flutter_')):
            if key and key != 'flutter':
                keys.setdefault(key, base)
    return keys


def _plugin_package(name, keys):
    for seg in name.split('/')[1:]:
        for key in sorted(keys, key=len, reverse=True):
            if seg == key or seg.startswith(key + '_'):
                return keys[key]
    return None


def _native_files(app_dir, rel_paths):
    """(path, string regex) of Android dex files and iOS executables."""
    files = []
    bundles = set()
    for rel in rel_paths:
        parts = PurePosixPath(rel.replace('\\', '/')).parts
        if not parts:
            continue
        if DEX_RE.match(parts[-1]):
            full = safe_join(app_dir, rel)
            if full:
                files.append((full, DEX_STRING_RE))
        for i, part in enumerate(parts[:-1]):
            if part.endswith('.app'):
                bundles.add('/'.join(parts[:i + 1]))
                break
    for bundle in sorted(bundles):
        exe = ios_executable(app_dir, bundle)
        if exe:
            files.append((exe, C_STRING_RE))
    return files[:MAX_NATIVE_FILES]


def _native_names(app_dir, rel_paths):
    """Channel-shaped strings of the app's native code."""
    names = set()
    for path, regex in _native_files(app_dir, rel_paths):
        for match in scan_regex(path, regex, tail=1024) or []:
            name = match.groups()[-1]
            # dex: the length byte must match (one byte up to 127)
            if regex is DEX_STRING_RE and match.group(1)[0] != len(name):
                continue
            names.add(name.decode())
            if len(names) >= MAX_CANDIDATES:
                return names
    return names


def _in_dart(snapshot, names):
    """Names the Dart snapshot contains, starting at a boundary."""
    if not names:
        return set()
    regex = re.compile(NAME_START + b'(' + b'|'.join(
        re.escape(n.encode())
        for n in sorted(names, key=len, reverse=True)) + b')')
    return {m.group(1).decode()
            for m in scan_regex(snapshot, regex, tail=1024) or []}


def binary_channels(app_dir, rel_paths, snapshot, packages):
    """Attributed platform channels of an extracted APK or IPA."""
    if not snapshot:
        return []
    try:
        names = set()
        for match in scan_regex(snapshot, CHANNEL_RE, tail=1024) or []:
            name = match.group(1).decode()
            if not name.startswith(ENGINE_PREFIXES):
                names.add(name)
        pigeon = {}
        for match in scan_regex(snapshot, PIGEON_RE, tail=1024) or []:
            pigeon.setdefault(match.group(1).decode(), set()).add(
                match.group(0))
        native = _native_names(app_dir, rel_paths)
        keys = _package_keys(packages)
        rows = []
        for name in sorted(names | native)[:MAX_CANDIDATES]:
            package = _plugin_package(name, keys)
            if package:
                rows.append(_row(name, 'plugin', package))
        unattributed = [n for n in native if not _plugin_package(n, keys)]
        for name in _in_dart(snapshot, unattributed):
            if not name.startswith(ENGINE_PREFIXES):
                rows.append(_row(name, 'app'))
    except Exception:
        logger.exception('Failed to list Flutter platform channels')
        return []
    for package, found in pigeon.items():
        rows.append(_row(f'dev.flutter.pigeon.{package}.*', 'pigeon',
                         base_package(package), len(found)))
    return sorted(rows, key=lambda r: (r['kind'], r['name']))


def _read_text(path):
    try:
        fobj = open_regular(path, MAX_DART_SIZE)
        if fobj is None:
            return None
        with fobj:
            return fobj.read(MAX_DART_SIZE + 1).decode('utf-8', 'ignore')
    except OSError:
        return None


def _walk(root, start, skip, exts):
    """Yield (rel path, text) of files under start, up to MAX_DART_FILES."""
    seen = 0
    for dirpath, dirnames, filenames in os.walk(start):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        prefix = '' if rel_dir == '.' else rel_dir + '/'
        dirnames[:] = sorted(d for d in dirnames if not skip(prefix, d))
        for fname in sorted(filenames):
            if not fname.endswith(exts):
                continue
            seen += 1
            if seen > MAX_DART_FILES:
                return
            text = _read_text(Path(dirpath) / fname)
            if text is not None:
                yield prefix + fname, text


def _native_handlers(root, names):
    """Native files in android/ and ios/ that quote a channel name."""
    found = {}
    if not names:
        return found
    quoted = {name: f'"{name}"' for name in names}
    for top in NATIVE_DIRS:
        start = root / top
        if is_pipe_or_link(start) or not start.is_dir():
            continue
        for rel, text in _walk(root, start,
                               lambda _p, d: d in NATIVE_SKIP, NATIVE_EXTS):
            for name, needle in quoted.items():
                if needle in text:
                    found.setdefault(name, set()).add(rel)
    return found


def source_channels(root):
    """App platform channels named in a Flutter project's Dart sources."""
    root = Path(root)
    found = {}
    for rel, text in _walk(
            root, root, lambda p, d: f'{p}{d}/' in IGNORED_DIRS, ('.dart',)):
        for match in SOURCE_RE.finditer(text):
            found.setdefault(match.group(2), set()).add(rel)
    native = _native_handlers(root, list(found))
    return [_row(name, 'app', files=files, native_files=native.get(name))
            for name, files in sorted(found.items())]
