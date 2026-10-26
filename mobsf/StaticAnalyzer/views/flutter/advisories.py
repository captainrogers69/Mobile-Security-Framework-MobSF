# -*- coding: utf_8 -*-
"""Match Dart/Flutter versions against Dart SDK security advisories.

dart_advisories.json is curated from
https://github.com/dart-lang/sdk/security/advisories and keeps only
advisories that affect compiled Android/iOS apps at runtime (not pub or
tooling issues, not dart:html).
"""
import json
from functools import lru_cache
from pathlib import Path

DATA_FILE = Path(__file__).resolve().parent / 'dart_advisories.json'
SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}


def _vkey(ver):
    return tuple(int(x) for x in ver.split('.'))


@lru_cache(maxsize=1)
def load_advisories():
    """Load curated advisories."""
    with DATA_FILE.open(encoding='utf-8') as fobj:
        return json.load(fobj)


def check_advisories(platform, dart=None, flutter=None):
    """Return advisories affecting an app.

    flutter: exact Flutter version candidates (from the engine revision),
    preferred over dart: Dart versions sharing the app's snapshot hash.
    status is 'affected' when every candidate is below the fixed version,
    'possibly affected' when only some are.
    """
    if flutter:
        candidates, field = flutter, 'fixed_flutter'
    elif dart:
        candidates, field = dart, 'fixed_dart'
    else:
        return []
    results = []
    for adv in load_advisories():
        if platform not in adv['platforms']:
            continue
        fixed = _vkey(adv[field])
        below = [v for v in candidates if _vkey(v) < fixed]
        if not below:
            continue
        status = ('affected' if len(below) == len(candidates)
                  else 'possibly affected')
        results.append({**adv, 'status': status})
    return sorted(
        results, key=lambda a: (SEVERITY_ORDER[a['severity']], a['id']))
