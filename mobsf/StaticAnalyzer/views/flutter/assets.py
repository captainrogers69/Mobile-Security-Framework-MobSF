# -*- coding: utf_8 -*-
"""Flag sensitive files bundled in flutter_assets/ and scan their secrets.

audit_assets() inspects file names only. Certificate, key and keystore
extensions (.pem, .key, .p12, .jks, ...) are left to
get_hardcoded_cert_keystore, which already scans every file in the app.
asset_secrets() reads the flagged text assets (attacker-controlled).
"""
import json
import logging
import re
from pathlib import Path, PurePosixPath

from mobsf.MobSF.security import (
    is_path_traversal,
    is_safe_path,
    sanitize_for_logging,
)
from mobsf.StaticAnalyzer.views.common.secret_detection import (
    detect_known_secrets,
    sort_secrets,
)
from mobsf.StaticAnalyzer.views.common.shared_func import is_secret_key
from mobsf.StaticAnalyzer.views.flutter.fileio import open_regular

logger = logging.getLogger(__name__)

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
# Asset types whose content is text worth scanning for secrets
TEXT_TYPES = ('env', 'firebase', 'config', 'key')
MAX_ASSET_SIZE = 1024 * 1024
MAX_VALUE = 500
CONTROL_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
LINE_RE = re.compile(
    r'^\s*(?:export\s+)?["\']?([A-Za-z_][A-Za-z0-9_.\-]{0,99})["\']?'
    r'\s*[:=]\s*(.*?)\s*,?\s*$')
PLIST_RE = re.compile(
    r'<key>\s*([^<]{1,100}?)\s*</key>\s*'
    r'<string>\s*([^<]{0,500}?)\s*</string>')


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


def classify_assets(rel_paths):
    """Return sorted [{'file', 'type'}] for sensitive files by name."""
    found = {}
    for rel in rel_paths:
        rel = rel.replace('\\', '/')
        parts = PurePosixPath(rel).parts
        if not parts:
            continue
        asset_type = _asset_type(parts[-1])
        if asset_type:
            found[rel] = asset_type
    return [{'file': f, 'type': t} for f, t in sorted(found.items())]


def audit_assets(rel_paths):
    """Return sorted [{'file', 'type'}] for sensitive flutter_assets files."""
    return classify_assets(
        rel for rel in rel_paths
        if FLUTTER_ASSETS in PurePosixPath(rel.replace('\\', '/')).parts[:-1])


def _json_pairs(text):
    """Return (key, value) string pairs from JSON, or None if not JSON."""
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return None
    pairs = []
    stack = [data]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, str):
                    pairs.append((str(key), value))
                elif isinstance(value, (dict, list)):
                    stack.append(value)
        elif isinstance(node, list):
            stack.extend(i for i in node if isinstance(i, (dict, list)))
    return pairs


def _pairs(text):
    """Extract key/value pairs from env, properties, YAML, JSON or plist."""
    pairs = _json_pairs(text)
    if pairs is None:
        pairs = []
        for line in text.splitlines():
            match = LINE_RE.match(line)
            if match:
                pairs.append(
                    (match.group(1), match.group(2).strip('"\'')))
    pairs.extend(PLIST_RE.findall(text))
    return pairs


def _secrets(text):
    secrets = set()
    for key, value in _pairs(text):
        value = value[:MAX_VALUE]
        if value and ' ' not in value and is_secret_key(key):
            secrets.add(f'"{key}" : "{value}"')
    secrets.update(detect_known_secrets(text))
    return secrets


def asset_secrets(base_dir, audit, max_size=MAX_ASSET_SIZE):
    """Scan flagged text assets for secrets.

    audit is the output of audit_assets() with paths relative to base_dir.
    Returns sorted [{'file', 'secrets'}] for files with findings.
    """
    results = []
    for item in audit:
        rel = item.get('file', '')
        if item.get('type') not in TEXT_TYPES or is_path_traversal(rel):
            continue
        full = Path(base_dir) / rel
        if not is_safe_path(base_dir, full, rel):
            continue
        try:
            fobj = open_regular(full, max_size)
            if fobj is None:
                continue
            with fobj:
                data = fobj.read(max_size + 1)
        except OSError:
            logger.warning(
                'Failed to read Flutter asset %s', sanitize_for_logging(rel))
            continue
        text = CONTROL_RE.sub('', data.decode('utf-8', 'ignore'))
        secrets = _secrets(text)
        if secrets:
            results.append({'file': rel, 'secrets': sort_secrets(secrets)})
    return sorted(results, key=lambda r: r['file'])
