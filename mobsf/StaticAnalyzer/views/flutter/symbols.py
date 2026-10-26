# -*- coding: utf_8 -*-
"""Dart API usage visible as names in non-obfuscated AOT snapshots.

Method names of used Dart APIs survive in non-obfuscated snapshots
(webview_flutter's addJavaScriptChannel appears only when called);
--obfuscate removes them, so absence proves nothing for obfuscated apps.
webview_flutter 2.x/3.x always compiles in its own addJavaScriptChannel
and keeps it in platform channel names, so there the name proves nothing.
"""
import logging
import re

from mobsf.StaticAnalyzer.views.flutter.fileio import scan_regex

logger = logging.getLogger(__name__)

# A dot before the name is a platform channel name, not a Dart method
JS_CHANNEL_RE = re.compile(
    rb'(?<![A-Za-z0-9_$.])addJavaScriptChannel(?![A-Za-z0-9_$])')
# Class of the webview_flutter 2.x/3.x platform interface
WEBVIEW_3X_RE = re.compile(
    rb'(?<![A-Za-z0-9_$])JavascriptChannelRegistry(?![A-Za-z0-9_$])')


def uses_js_channels(path):
    """True/False if a snapshot calls addJavaScriptChannel, None if unknown."""
    try:
        matches = scan_regex(path, JS_CHANNEL_RE, tail=64, first_only=True)
        if matches and scan_regex(
                path, WEBVIEW_3X_RE, tail=64, first_only=True):
            return None
    except FileNotFoundError:
        return None
    except Exception:
        logger.exception('Failed to scan Dart snapshot for JS channels')
        return None
    if matches is None:
        return None
    return bool(matches)
