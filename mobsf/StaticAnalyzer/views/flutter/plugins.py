# -*- coding: utf_8 -*-
"""Inventory Flutter plugins from native code (works on obfuscated apps).

Android: GeneratedPluginRegistrant keeps the string constant
"Error registering plugin <pub package>, <plugin class>" in classes*.dex.
iOS: Swift plugins linked into the app executable keep mangled class
names _TtC<len><module><len><class>, the module being the pub package;
CocoaPods builds ship each plugin as Frameworks/<pub package>.framework.
"""
import logging
import plistlib
import re
from pathlib import Path, PurePosixPath

from mobsf.MobSF.security import (
    is_path_traversal,
    is_safe_path,
)
from mobsf.StaticAnalyzer.views.flutter.fileio import (
    open_regular,
    scan_regex,
)

logger = logging.getLogger(__name__)

REGISTRANT_RE = re.compile(
    rb'Error registering plugin ([a-z0-9_]{1,64}), ([A-Za-z0-9_.$]{1,200})')
MANGLED_RE = re.compile(rb'_TtC([0-9]{1,3}[A-Za-z0-9_]{1,400})')
DEX_RE = re.compile(r'^classes[0-9]*\.dex$')
PUB_NAME_RE = re.compile(r'^[a-z][a-z0-9_]{0,63}$')
EXE_RE = re.compile(r'^[A-Za-z0-9_. -]{1,100}$')
# Federated plugin implementation suffixes
PLATFORM_SUFFIXES = ('_android', '_ios', '_foundation', '_darwin',
                     '_wkwebview', '_macos', '_linux', '_windows', '_web',
                     '_apple')
PLIST_MAX_SIZE = 1024 * 1024


def base_package(name):
    """Map a federated implementation package to the app-facing one."""
    for suffix in PLATFORM_SUFFIXES:
        if name.endswith(suffix) and len(name) > len(suffix):
            return name[:-len(suffix)]
    return name


def _demangle_plugin(run):
    """Return (module, class) from '<n><module><m><class>', else None."""
    run = run.decode('ascii')
    digits = re.match(r'[0-9]+', run).group()
    rest = run[len(digits):]
    module = rest[:int(digits)]
    rest = rest[int(digits):]
    if len(module) != int(digits) or not PUB_NAME_RE.match(module):
        return None
    match = re.match(r'[0-9]+', rest)
    if not match:
        return None
    size = int(match.group())
    cls = rest[len(match.group()):][:size]
    if len(cls) != size or not cls.endswith('Plugin'):
        return None
    return module, cls


def _safe_file(app_dir, rel):
    rel = rel.replace('\\', '/')
    if is_path_traversal(rel):
        return None
    full = Path(app_dir) / rel
    if not is_safe_path(app_dir, full, rel):
        return None
    return full


def _ios_executable(app_dir, app_rel):
    """Return the main executable path of a .app bundle, else None."""
    plist = _safe_file(app_dir, f'{app_rel}/Info.plist')
    if plist is None:
        return None
    try:
        fobj = open_regular(plist, PLIST_MAX_SIZE)
        if fobj is None:
            return None
        with fobj:
            data = plistlib.loads(fobj.read(PLIST_MAX_SIZE + 1))
    except Exception:
        return None
    exe = data.get('CFBundleExecutable') if isinstance(data, dict) else None
    if (not isinstance(exe, str) or not EXE_RE.match(exe)
            or exe.strip('.') == '' or '..' in exe):
        return None
    return _safe_file(app_dir, f'{app_rel}/{exe}')


def _add(found, platform, name, cls):
    found.setdefault((platform, name), {
        'name': name,
        'package': base_package(name),
        'class': cls,
        'platform': platform,
    })


def flutter_plugins(app_dir, rel_paths):
    """Return sorted Flutter plugins found in an extracted APK or IPA."""
    found = {}
    app_bundles = set()
    for rel in rel_paths:
        parts = PurePosixPath(rel.replace('\\', '/')).parts
        if not parts:
            continue
        try:
            if DEX_RE.match(parts[-1]):
                full = _safe_file(app_dir, rel)
                for match in (scan_regex(full, REGISTRANT_RE) or [] if full else []):
                    _add(found, 'android', match.group(1).decode(),
                         match.group(2).decode())
        except Exception:
            logger.exception('Failed to read Flutter plugin registrant')
        for i, part in enumerate(parts[:-1]):
            if part.endswith('.app'):
                app_bundles.add('/'.join(parts[:i + 1]))
                after = parts[i + 1:]
                if (len(after) >= 2 and after[0] == 'Frameworks'
                        and after[1].endswith('.framework')):
                    name = after[1][:-len('.framework')]
                    if PUB_NAME_RE.match(name):
                        _add(found, 'ios', name, None)
                break
    for app_rel in sorted(app_bundles):
        try:
            exe = _ios_executable(app_dir, app_rel)
            for match in (scan_regex(exe, MANGLED_RE) or [] if exe else []):
                plugin = _demangle_plugin(match.group(1))
                if plugin:
                    _add(found, 'ios', *plugin)
        except Exception:
            logger.exception('Failed to read iOS plugin classes')
    return sorted(found.values(), key=lambda p: (p['platform'], p['name']))
