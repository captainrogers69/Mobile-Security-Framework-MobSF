# -*- coding: utf_8 -*-
"""Dart API usage visible as names in non-obfuscated AOT snapshots.

Method names of used Dart APIs survive in non-obfuscated snapshots
(webview_flutter's addJavaScriptChannel appears only when called);
--obfuscate removes them, so absence proves nothing for obfuscated apps.
"""
import logging
import re

from mobsf.StaticAnalyzer.views.flutter.fileio import scan_regex

logger = logging.getLogger(__name__)

JS_CHANNEL_RE = re.compile(
    rb'(?<![A-Za-z0-9_$])addJavaScriptChannel(?![A-Za-z0-9_$])')


def uses_js_channels(path):
    """True/False if a snapshot calls addJavaScriptChannel, None if unknown."""
    try:
        matches = scan_regex(path, JS_CHANNEL_RE, tail=64, first_only=True)
    except FileNotFoundError:
        return None
    except Exception:
        logger.exception('Failed to scan Dart snapshot for JS channels')
        return None
    if matches is None:
        return None
    return bool(matches)
