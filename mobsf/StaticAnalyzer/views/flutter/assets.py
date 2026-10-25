# -*- coding: utf_8 -*-
"""Flag sensitive files bundled in flutter_assets/.

Only file names are inspected. Certificate, key and keystore extensions
(.pem, .key, .p12, .jks, ...) are left to get_hardcoded_cert_keystore,
which already scans every file in the app.
"""
from pathlib import PurePosixPath

FLUTTER_ASSETS = 'flutter_assets'
FIREBASE_FILES = ('google-services.json', 'GoogleService-Info.plist')
SSH_KEYS = ('id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519')
KEY_EXT = ('.p8', '.keystore')
DB_EXT = ('.db', '.sqlite', '.sqlite3', '.realm', '.hive')
CONFIG_EXT = ('.json', '.yaml', '.yml', '.xml', '.plist', '.properties',
              '.toml', '.ini', '.cfg', '.conf')
CONFIG_WORDS = ('config', 'secret', 'credential', 'setting', 'token',
                'api_key', 'apikey', 'api-key', 'auth', 'password',
                'private')


def _asset_type(name):
    """Return the sensitive asset type for a file name, else None."""
    lower = name.lower()
    suffix = PurePosixPath(lower).suffix
    if lower == '.env' or lower.startswith('.env.') or lower.endswith('.env'):
        return 'env'
    if name in FIREBASE_FILES or (
            lower.startswith('firebase') and suffix in CONFIG_EXT):
        return 'firebase'
    if lower in SSH_KEYS or suffix in KEY_EXT:
        return 'key'
    if suffix in DB_EXT:
        return 'database'
    if suffix in CONFIG_EXT and any(w in lower for w in CONFIG_WORDS):
        return 'config'
    return None


def audit_assets(rel_paths):
    """Return sorted [{'file', 'type'}] for sensitive flutter_assets files."""
    found = {}
    for rel in rel_paths:
        rel = rel.replace('\\', '/')
        parts = PurePosixPath(rel).parts
        if len(parts) < 2 or FLUTTER_ASSETS not in parts[:-1]:
            continue
        asset_type = _asset_type(parts[-1])
        if asset_type:
            found[rel] = asset_type
    return [{'file': f, 'type': t} for f, t in sorted(found.items())]
