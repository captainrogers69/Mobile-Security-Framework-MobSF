# -*- coding: utf_8 -*-
"""Flutter project (source ZIP) detection and pubspec.lock parsing.

pubspec.yaml and pubspec.lock come from the uploaded ZIP and are
attacker-controlled: they are read through open_regular() with a size
cap and parsed with yaml safe loading only.
"""
import logging
import re
from pathlib import Path

import yaml

from mobsf.MobSF.security import is_pipe_or_link
from mobsf.StaticAnalyzer.views.flutter.fileio import open_regular

logger = logging.getLogger(__name__)

MAX_YAML_SIZE = 2 * 1024 * 1024
NAME_RE = re.compile(r'^[a-z_][a-z0-9_]{0,63}$')
VERSION_RE = re.compile(r'^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-+]{1,64})?$')
SOURCES = ('hosted', 'git', 'path', 'sdk')
DEPENDENCY_TYPES = ('direct main', 'direct dev', 'direct overridden',
                    'transitive')
SafeLoader = getattr(yaml, 'CSafeLoader', yaml.SafeLoader)


def load_yaml(path, max_size=MAX_YAML_SIZE):
    """Safely load a small YAML file, or None."""
    try:
        fobj = open_regular(path, max_size)
        if fobj is None:
            return None
        with fobj:
            return yaml.load(fobj.read(max_size + 1), Loader=SafeLoader)
    except FileNotFoundError:
        return None
    except (yaml.YAMLError, OSError, ValueError):
        logger.warning('Failed to parse %s', Path(path).name)
        return None


def _is_flutter_pubspec(path):
    data = load_yaml(path)
    if not isinstance(data, dict):
        return False
    deps = data.get('dependencies')
    flutter = deps.get('flutter') if isinstance(deps, dict) else None
    return isinstance(flutter, dict) and flutter.get('sdk') == 'flutter'


def is_flutter_source(app_path):
    """Return the Flutter project root (app_path or one level down)."""
    app_path = Path(app_path)
    candidates = [app_path]
    try:
        candidates += sorted(
            d for d in app_path.iterdir()
            if not is_pipe_or_link(d) and d.is_dir())
    except OSError:
        pass
    for candidate in candidates:
        if _is_flutter_pubspec(candidate / 'pubspec.yaml'):
            return candidate
    return None


def pubspec_lock_packages(lock_path, max_size=MAX_YAML_SIZE):
    """Return sorted [{'name', 'version', 'source', 'dependency'}]."""
    data = load_yaml(lock_path, max_size)
    packages = data.get('packages') if isinstance(data, dict) else None
    if not isinstance(packages, dict):
        return []
    result = []
    for name, entry in packages.items():
        if not isinstance(name, str) or not NAME_RE.match(name):
            continue
        if not isinstance(entry, dict):
            continue
        version = entry.get('version')
        source = entry.get('source')
        if (not isinstance(version, str) or not VERSION_RE.match(version)
                or source not in SOURCES):
            continue
        dependency = entry.get('dependency')
        result.append({
            'name': name,
            'version': version,
            'source': source,
            'dependency': (dependency if dependency in DEPENDENCY_TYPES
                           else ''),
        })
    return sorted(result, key=lambda p: p['name'])
