# -*- coding: utf-8 -*-
"""Flutter deep linking flags.

When enabled, Flutter pushes the path of an incoming deep link to the
app's router. Android: <meta-data android:name="flutter_deeplinking_enabled"
android:value="true"/> in the manifest. iOS: FlutterDeepLinkingEnabled in
Info.plist.
"""
ANDROID_NS = 'http://schemas.android.com/apk/res/android'
ANDROID_FLAG = 'flutter_deeplinking_enabled'
IOS_FLAG = 'FlutterDeepLinkingEnabled'


def android_deep_linking(parsed_manifest):
    """True/False from a parsed (defusedxml minidom) manifest, else None."""
    if parsed_manifest is None:
        return None
    try:
        for node in parsed_manifest.getElementsByTagName('meta-data'):
            name = node.getAttributeNS(ANDROID_NS, 'name')
            if name != ANDROID_FLAG:
                continue
            value = node.getAttributeNS(ANDROID_NS, 'value').strip().lower()
            if value in ('true', 'false'):
                return value == 'true'
            return None
    except Exception:
        return None
    return None


def ios_deep_linking(info_plist):
    """True/False from a parsed Info.plist dict, else None."""
    if not isinstance(info_plist, dict):
        return None
    value = info_plist.get(IOS_FLAG)
    return value if isinstance(value, bool) else None
