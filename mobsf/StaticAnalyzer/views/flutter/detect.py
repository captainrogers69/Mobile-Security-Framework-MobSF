# -*- coding: utf_8 -*-
"""Detect Flutter apps from the extracted file layout.

Only file names are inspected; file contents are never read here.
"""
import logging
import os
from pathlib import PurePosixPath

logger = logging.getLogger(__name__)

FLUTTER_ASSETS = 'flutter_assets'
ANDROID_ENGINE = 'libflutter.so'
ANDROID_SNAPSHOT = 'libapp.so'
# Only shipped in debug (JIT) builds; the Dart kernel holds recoverable code
KERNEL_BLOB = 'kernel_blob.bin'


def _abi(parts):
    """Return the ABI for lib/<abi>/<name>, else None."""
    if len(parts) >= 3 and parts[-3] == 'lib':
        return parts[-2]
    return None


def detect_flutter(rel_paths):
    """Detect Flutter from relative paths of an extracted app."""
    engine = set()
    app_snapshot = set()
    debug_artifacts = set()
    abis = set()
    has_assets = False
    for rel in rel_paths:
        rel = rel.replace('\\', '/')
        parts = PurePosixPath(rel).parts
        if not parts:
            continue
        name = parts[-1]
        parent = parts[-2] if len(parts) > 1 else ''
        if FLUTTER_ASSETS in parts[:-1]:
            has_assets = True
            if name == KERNEL_BLOB and parent == FLUTTER_ASSETS:
                debug_artifacts.add(rel)
        if name in (ANDROID_ENGINE, ANDROID_SNAPSHOT):
            abi = _abi(parts)
            if abi:
                abis.add(abi)
            if name == ANDROID_ENGINE:
                engine.add(rel)
            else:
                app_snapshot.add(rel)
        elif parent == 'Flutter.framework' and name == 'Flutter':
            engine.add(rel)
        elif parent == 'App.framework' and name == 'App':
            app_snapshot.add(rel)
    is_flutter = bool(engine) or has_assets
    if not is_flutter:
        build_mode = 'unknown'
    elif debug_artifacts:
        build_mode = 'debug'
    elif app_snapshot:
        build_mode = 'release'
    else:
        build_mode = 'unknown'
    return {
        'is_flutter': is_flutter,
        'build_mode': build_mode,
        'abis': sorted(abis),
        'engine': sorted(engine),
        'app_snapshot': sorted(app_snapshot) if is_flutter else [],
        'debug_artifacts': sorted(debug_artifacts),
    }


def flutter_from_dir(app_dir):
    """Detect Flutter by walking an extracted app directory."""
    rel_paths = []
    try:
        # os.walk does not follow directory symlinks by default
        for root, _dirs, files in os.walk(app_dir):
            rel_root = os.path.relpath(root, app_dir)
            for name in files:
                rel_paths.append(
                    PurePosixPath(rel_root, name).as_posix()
                    if rel_root != '.' else name)
    except Exception:
        logger.exception('Failed to walk directory for Flutter detection')
    return detect_flutter(rel_paths)
