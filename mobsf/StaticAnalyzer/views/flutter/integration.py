# -*- coding: utf_8 -*-
"""Run Flutter analysis inside MobSF scans and persist its result.

The result is stored as a per-scan state file (flutter.json), so no
database schema change is needed; deleting a scan removes it.
"""
import json
import logging
import os
import plistlib
from pathlib import Path

from django.conf import settings

from mobsf.MobSF.security import is_pipe_or_link
from mobsf.MobSF.utils import (
    append_scan_status,
    is_md5,
    scan_state_file,
)
from mobsf.StaticAnalyzer.views.flutter.binary import flutter_binary_analysis
from mobsf.StaticAnalyzer.views.flutter.fileio import open_regular
from mobsf.StaticAnalyzer.views.flutter.source import is_flutter_source
from mobsf.StaticAnalyzer.views.flutter.source_analysis import (
    flutter_source_analysis,
)

logger = logging.getLogger(__name__)

STATE_NAME = 'flutter.json'
MAX_RESULT_SIZE = 20 * 1024 * 1024
MAX_FILES = 300000
PLIST_MAX_SIZE = 1024 * 1024
# MobSF output in the scan folder: apktool's copy of the APK and the
# decompiled sources (left over on rescans)
MOBSF_OUTPUT_DIRS = ('apktool_out', 'java_source', 'smali_source')


def save_result(checksum, result):
    """Persist a Flutter result for a scan."""
    path = scan_state_file(checksum, STATE_NAME)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result), encoding='utf-8')


def _clear_result(checksum):
    path = scan_state_file(checksum, STATE_NAME)
    if path.is_file() and not path.is_symlink():
        path.unlink()


def load_result(checksum):
    """Return the saved Flutter result of a scan, or None."""
    try:
        fobj = open_regular(scan_state_file(checksum, STATE_NAME),
                            MAX_RESULT_SIZE)
        if fobj is None:
            return None
        with fobj:
            data = json.loads(fobj.read(MAX_RESULT_SIZE + 1))
    except (ValueError, OSError):
        return None
    return data if isinstance(data, dict) else None


# Reports a request may ask for when a scan hash has more than one
PLATFORMS = ('ios',)


def requested_platform(request):
    """'ios' when a request asks for the iOS report of a scan, else None."""
    if request is None:
        return None
    value = request.GET.get('platform') or request.POST.get('platform')
    return value if value in PLATFORMS else None


def flutter_ios_dir(app_dir):
    """ios/ of a Flutter project with an Xcode project ('<path>/'), or None."""
    root = is_flutter_source(app_dir)
    if root is None:
        return None
    ios = root / 'ios'
    if is_pipe_or_link(ios) or not ios.is_dir():
        return None
    if not any(p.suffix == '.xcodeproj' and not is_pipe_or_link(p)
               and p.is_dir() for p in ios.iterdir()):
        return None
    return ios.as_posix() + '/'


def _rel_files(app_dir):
    """Relative posix paths of files under app_dir (links not followed)."""
    files = []
    for root, dirs, names in os.walk(app_dir):
        rel_root = os.path.relpath(root, app_dir)
        if rel_root == '.':
            dirs[:] = [d for d in dirs if d not in MOBSF_OUTPUT_DIRS]
        for name in names:
            files.append(Path(rel_root, name).as_posix()
                         if rel_root != '.' else name)
            if len(files) >= MAX_FILES:
                return files
    return files


def _ios_info_plist(app_dir, files):
    """Parsed Info.plist of the .app bundle in an extracted IPA."""
    for rel in files:
        parts = rel.split('/')
        if (len(parts) == 3 and parts[0] == 'Payload'
                and parts[1].endswith('.app') and parts[2] == 'Info.plist'):
            try:
                fobj = open_regular(Path(app_dir) / rel, PLIST_MAX_SIZE)
                if fobj is None:
                    return None
                with fobj:
                    data = plistlib.loads(fobj.read(PLIST_MAX_SIZE + 1))
                return data if isinstance(data, dict) else None
            except Exception:
                return None
    return None


def scan_binary(checksum, app_dir, platform, parsed_manifest=None):
    """Flutter analysis of an extracted APK/IPA; None on failure."""
    if not is_md5(checksum):
        return None
    try:
        files = _rel_files(app_dir)
        info_plist = (_ios_info_plist(app_dir, files)
                      if platform == 'ios' else None)
        result = flutter_binary_analysis(
            app_dir, files, platform,
            parsed_manifest=parsed_manifest, info_plist=info_plist)
        _store(checksum, result)
        return result
    except Exception as exp:
        msg = 'Flutter Analysis Failed'
        logger.exception(msg)
        _status(checksum, msg, repr(exp))
        return None


def scan_source(checksum, app_dir):
    """Flutter analysis of an extracted project ZIP; None on failure."""
    if not is_md5(checksum):
        return None
    try:
        result = flutter_source_analysis(
            app_dir,
            osv_enabled=getattr(settings, 'FLUTTER_OSV_ENABLED', False),
            checksum=checksum)
        _store(checksum, result)
        return result
    except Exception as exp:
        msg = 'Flutter Source Analysis Failed'
        logger.exception(msg)
        _status(checksum, msg, repr(exp))
        return None


def _store(checksum, result):
    if result.get('is_flutter'):
        save_result(checksum, result)
        _status(checksum, 'Flutter Analysis Completed')
    else:
        # A rescan of the same hash must not show a stale result
        _clear_result(checksum)


def _status(checksum, msg, err=''):
    try:
        append_scan_status(checksum, msg, err)
    except Exception:
        pass
