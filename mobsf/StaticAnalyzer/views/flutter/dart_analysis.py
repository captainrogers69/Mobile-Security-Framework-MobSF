# -*- coding: utf_8 -*-
"""Dart source code analysis for Flutter project ZIPs."""
from functools import lru_cache
from pathlib import Path

import yaml

from mobsf.StaticAnalyzer.views.sast_engine import SastEngine

RULES = Path(__file__).resolve().parent / 'rules' / 'dart_rules.yaml'
# Generated and dependency code inside the project root
IGNORED_DIRS = ('.dart_tool/', 'build/', '.pub-cache/', 'ios/.symlinks/')


@lru_cache(maxsize=1)
def load_dart_rules():
    """Load the Dart rules."""
    with RULES.open(encoding='utf-8') as fobj:
        return yaml.safe_load(fobj)


def dart_code_analysis(project_root):
    """Run the Dart rules over a Flutter project, MobSF findings format."""
    src = Path(project_root).as_posix().rstrip('/') + '/'
    options = {
        'match_rules': RULES.as_posix(),
        'match_extensions': {'.dart'},
        'ignore_paths': [src + d for d in IGNORED_DIRS],
    }
    return SastEngine(options, src).scan()
