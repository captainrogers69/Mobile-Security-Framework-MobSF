# -*- coding: utf_8 -*-
"""Read the Dart snapshot header from a Flutter AOT binary.

Layout (dart-lang/sdk runtime/vm/snapshot.h, app_snapshot.cc):
int32 magic, int64 length, int64 kind, then the snapshot version hash
(Version::SnapshotString) and a NUL-terminated features string.
"""
import logging
import re

from mobsf.StaticAnalyzer.views.flutter.fileio import open_regular

logger = logging.getLogger(__name__)

MAGIC = b'\xf5\xf5\xdc\xdc'  # 0xdcdcf5f5, little endian
HEADER_SIZE = 20
HASH_SIZE = 32
FEATURES_MAX = 1024
NEEDED = HEADER_SIZE + HASH_SIZE + FEATURES_MAX
MAX_SIZE = 512 * 1024 * 1024
CHUNK_SIZE = 4 * 1024 * 1024
HASH_RE = re.compile(rb'^[0-9a-f]{32}$')
FEATURE_RE = re.compile(r'^[A-Za-z0-9_.\-]+$')


def _parse(data):
    """Parse a header at the start of data, else None."""
    snap_hash = data[HEADER_SIZE:HEADER_SIZE + HASH_SIZE]
    if not HASH_RE.match(snap_hash):
        return None
    raw = data[HEADER_SIZE + HASH_SIZE:NEEDED].split(b'\x00', 1)[0]
    features = [
        f for f in raw.decode('ascii', 'replace').split(' ')
        if FEATURE_RE.match(f)]
    return {
        'snapshot_hash': snap_hash.decode('ascii'),
        'features': features,
    }


def read_snapshot_header(path, max_size=MAX_SIZE, chunk_size=CHUNK_SIZE):
    """Return the first valid Dart snapshot header in a file, or None."""
    try:
        fobj = open_regular(path, max_size)
        if fobj is None:
            return None
        with fobj:
            buf = b''
            while True:
                chunk = fobj.read(chunk_size)
                eof = not chunk
                buf += chunk
                start = 0
                while True:
                    pos = buf.find(MAGIC, start)
                    if pos == -1:
                        # Keep a partial magic that may span chunks
                        buf = buf[-(len(MAGIC) - 1):]
                        break
                    if len(buf) - pos < NEEDED and not eof:
                        # Need more data to parse this candidate
                        buf = buf[pos:]
                        break
                    res = _parse(buf[pos:pos + NEEDED])
                    if res:
                        return res
                    start = pos + 1
                if eof:
                    return None
    except FileNotFoundError:
        return None
    except Exception:
        logger.exception('Failed to read Dart snapshot header')
    return None
