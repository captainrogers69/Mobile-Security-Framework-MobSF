# -*- coding: utf_8 -*-
"""Detect Dart obfuscation and split debug info in a Flutter AOT snapshot.

--split-debug-info sets the dwarf_stack_traces_mode snapshot feature.
--obfuscate (only allowed together with --split-debug-info) renames
classes and libraries: a non-obfuscated snapshot keeps hundreds of
package:<name>/<path>.dart library URIs (the Flutter framework alone
has ~300), an obfuscated one only a handful.
"""
import logging
import re

from mobsf.StaticAnalyzer.views.flutter.fileio import open_regular

logger = logging.getLogger(__name__)

URI_RE = re.compile(
    rb'package:([a-z0-9_]{1,64})/(?:[A-Za-z0-9_\-]{1,64}/){0,10}'
    rb'[A-Za-z0-9_\-.]{1,64}\.dart')
TAIL = 1024
MAX_SIZE = 512 * 1024 * 1024
CHUNK_SIZE = 4 * 1024 * 1024
MAX_URIS = 20000
# Non-obfuscated builds have ~300 distinct URIs, obfuscated ones ~3
OBFUSCATED_BELOW = 20


def split_debug_info(features):
    """True/False from snapshot features, None if unknown."""
    features = features or []
    if 'dwarf_stack_traces_mode' in features:
        return True
    if 'no-dwarf_stack_traces_mode' in features:
        return False
    return None


def package_uris(path, max_size=MAX_SIZE, chunk_size=CHUNK_SIZE,
                 max_uris=MAX_URIS):
    """Return distinct package: library URIs found in a snapshot, or None."""
    uris = set()
    try:
        fobj = open_regular(path, max_size)
        if fobj is None:
            return None
        with fobj:
            buf = b''
            while len(uris) < max_uris:
                chunk = fobj.read(chunk_size)
                eof = not chunk
                buf += chunk
                for match in URI_RE.finditer(buf):
                    # The URI may continue in the next chunk
                    if match.end() == len(buf) and not eof:
                        continue
                    uris.add(match.group().decode('ascii'))
                    if len(uris) >= max_uris:
                        break
                if eof:
                    break
                buf = buf[-TAIL:]
    except FileNotFoundError:
        return None
    except Exception:
        logger.exception('Failed to read Dart library URIs')
        return None
    return uris


def obfuscation_info(path, features):
    """Return split debug info, obfuscation and package names."""
    split = split_debug_info(features)
    uris = package_uris(path)
    if uris is None:
        obfuscated = None
        uris = set()
    elif split is False:
        obfuscated = False
    else:
        obfuscated = len(uris) < OBFUSCATED_BELOW
    return {
        'split_debug_info': split,
        'obfuscated': obfuscated,
        'package_uris': len(uris),
        'packages': sorted({u.split(':', 1)[1].split('/', 1)[0]
                            for u in uris}),
    }
