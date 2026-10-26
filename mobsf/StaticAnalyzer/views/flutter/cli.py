# -*- coding: utf_8 -*-
"""Flutter analysis of a file or directory outside the web UI."""
import hashlib
import logging
import tempfile
from pathlib import Path

from defusedxml.minidom import parseString

from mobsf.StaticAnalyzer.tools.androguard4.axml import AXMLPrinter
from mobsf.StaticAnalyzer.views.common.shared_func import unzip
from mobsf.StaticAnalyzer.views.flutter.binary import flutter_binary_analysis
from mobsf.StaticAnalyzer.views.flutter.fileio import open_regular
from mobsf.StaticAnalyzer.views.flutter.integration import (
    _ios_info_plist,
    _rel_files,
)
from mobsf.StaticAnalyzer.views.flutter.source import is_flutter_source
from mobsf.StaticAnalyzer.views.flutter.source_analysis import (
    flutter_source_analysis,
)

logger = logging.getLogger(__name__)

AXML_MAGIC = b'\x03\x00\x08\x00'
MAX_MANIFEST_SIZE = 5 * 1024 * 1024
SEVERITY_RANK = {'high': 0, 'warning': 1, 'info': 2}


def _md5(path):
    digest = hashlib.md5()  # noqa: S324 (file identifier, not security)
    with open(path, 'rb') as fobj:
        for chunk in iter(lambda: fobj.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _android_manifest(app_dir):
    """Parsed AndroidManifest.xml (binary AXML or text), or None."""
    try:
        fobj = open_regular(Path(app_dir) / 'AndroidManifest.xml',
                            MAX_MANIFEST_SIZE)
        if fobj is None:
            return None
        with fobj:
            data = fobj.read(MAX_MANIFEST_SIZE + 1)
        if data.startswith(AXML_MAGIC):
            data = AXMLPrinter(data).get_xml()
        return parseString(data)
    except Exception:
        return None


def _scan_dir(app_dir, osv):
    if is_flutter_source(app_dir):
        return flutter_source_analysis(app_dir, osv_enabled=osv)
    files = _rel_files(app_dir)
    if any(f.startswith('Payload/') and '.app/' in f for f in files):
        return flutter_binary_analysis(
            app_dir, files, 'ios',
            info_plist=_ios_info_plist(app_dir, files))
    return flutter_binary_analysis(
        app_dir, files, 'android',
        parsed_manifest=_android_manifest(app_dir))


def scan_path(path, osv=False):
    """Analyse an APK/AAB/XAPK/IPA/ZIP file or a directory."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)
    if path.is_dir():
        return _scan_dir(path, osv)
    with tempfile.TemporaryDirectory() as tmp:
        # MobSF's unzip handles zip slip, size limits and encrypted entries
        unzip(_md5(path), path.as_posix(), tmp + '/')
        return _scan_dir(Path(tmp), osv)


def worst_severity(result):
    """Highest finding severity in a result, or None."""
    severities = [f.get('severity') for f in result.get('findings') or []]
    severities += [d.get('metadata', {}).get('severity')
                   for d in (result.get('code_analysis') or {}).values()]
    ranked = [s for s in severities if s in SEVERITY_RANK]
    return min(ranked, key=SEVERITY_RANK.get) if ranked else None
