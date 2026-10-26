# -*- coding: utf_8 -*-
"""Full MobSF iOS report for the ios/ app of a Flutter project ZIP.

A Flutter project ZIP gets MobSF's Android source report. When the
project has an Xcode project in ios/, MobSF's iOS source analysis also
runs on ios/ and stores an iOS report under the same scan hash: Android
and iOS reports live in separate tables, and deleting the scan removes
both. Requests pick it with platform=ios (see integration.requested_platform).
"""
import logging
from pathlib import Path

from django.conf import settings

from mobsf.MobSF.utils import is_md5
from mobsf.StaticAnalyzer.models import StaticAnalyzerIOS
from mobsf.StaticAnalyzer.views.flutter.integration import (
    _status,
    flutter_ios_dir,
    load_result,
    save_result,
)
from mobsf.StaticAnalyzer.views.ios.ipa import ios_analysis_task

logger = logging.getLogger(__name__)


def _ios_report_exists(checksum):
    return StaticAnalyzerIOS.objects.filter(MD5=checksum).exists()


def scan_ios_report(checksum, app_dic, rescan=False):
    """Run MobSF's iOS source analysis on ios/; True if a report exists."""
    if not isinstance(checksum, str) or not is_md5(checksum):
        return False
    try:
        ios_dir = flutter_ios_dir(app_dic['app_dir'])
        if not ios_dir:
            return False
        _status(checksum, 'Flutter project: iOS report of ios/')
        base = Path(settings.BASE_DIR)
        upload = Path(settings.UPLD_DIR) / checksum
        ios_dic = {
            'directory': base,
            'file_name': app_dic.get('app_name', ''),
            'md5_hash': checksum,
            'app_dirp': upload,
            'app_dir': ios_dir,
            'app_file': f'{checksum}.zip',
            'app_path': (upload / f'{checksum}.zip').as_posix(),
            'tools_dir': (base / 'StaticAnalyzer' / 'tools' / 'ios').as_posix(),
            'icon_path': '',
        }
        ios_analysis_task(
            checksum, ios_dic, rescan or _ios_report_exists(checksum))
        # MobSF's iOS task logs its own failures and returns None
        saved = _ios_report_exists(checksum)
        result = load_result(checksum)
        if result is not None:
            result['ios_report'] = saved
            save_result(checksum, result)
        return saved
    except Exception as exp:
        msg = 'Flutter iOS Report Failed'
        logger.exception(msg)
        _status(checksum, msg, repr(exp))
        return False
