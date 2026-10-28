#!/usr/bin/env python3
# -*- coding: utf_8 -*-
"""Regenerate the build-id -> offset table in the Flutter TLS bypass script.

For each Flutter engine revision it downloads the Android symbol archive
(unstripped libflutter.so), reads the GNU build-id and the offset of
bssl::ssl_verify_peer_cert, and rewrites the FLUTTER_SSL_OFFSETS block in
`mobsf/DynamicAnalyzer/tools/frida_scripts/flutter/ssl-bypass-flutter.js`.

The build-id is identical in the shipped (stripped) library and the
symbol archive, so the runtime script matches apps built with that engine.

Usage:
    python scripts/update_flutter_frida_offsets.py --engine <hash> [<hash> ...]
    python scripts/update_flutter_frida_offsets.py --lib arm64=path/to/libflutter.so

Engine revisions are the keys of flutter_engines.json. With no --engine,
the revisions already present in the table are refreshed.
"""
import argparse
import io
import json
import re
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

import lief

ROOT = Path(__file__).resolve().parent.parent / 'mobsf'
SCRIPT = (ROOT / 'DynamicAnalyzer' / 'tools' / 'frida_scripts' / 'flutter'
          / 'ssl-bypass-flutter.js')
ENGINES = (ROOT / 'StaticAnalyzer' / 'views' / 'flutter'
           / 'flutter_engines.json')
# Frida Process.arch -> Flutter release artifact directory
ARCHES = {'arm64': 'android-arm64-release', 'arm': 'android-arm-release'}
BASE = 'https://storage.googleapis.com/flutter_infra_release/flutter'
SYMBOL = '_ZN4bssl20ssl_verify_peer_certEPNS_13SSL_HANDSHAKEE'
BLOCK = re.compile(
    r'(var FLUTTER_SSL_OFFSETS\s*=\s*)\{.*?\}(;)', re.DOTALL)


def _build_id(binary):
    for note in binary.notes:
        if 'BUILD_ID' in str(note.type):
            return bytes(note.description).hex()
    return None


def _offset(binary):
    for sym in binary.symtab_symbols:
        if sym.name == SYMBOL:
            return sym.value
    return None


def _from_binary(data):
    with tempfile.NamedTemporaryFile(suffix='.so') as tmp:
        tmp.write(data)
        tmp.flush()
        binary = lief.parse(tmp.name)
    return _build_id(binary), _offset(binary)


def _download(engine, arch_dir):
    url = f'{BASE}/{engine}/{arch_dir}/symbols.zip'
    with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310
        archive = resp.read()
    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        with zf.open('libflutter.so') as fobj:
            return fobj.read()


def _parse_table():
    match = BLOCK.search(SCRIPT.read_text(encoding='utf-8'))
    return json.loads(match.group(0)[len('var FLUTTER_SSL_OFFSETS ='):
                                     -1].strip())


def _write_table(table):
    ordered = {k: dict(sorted(v.items())) for k, v in table.items()}
    body = ',\n'.join(f' {json.dumps(k)}: {json.dumps(v)}'
                      for k, v in ordered.items())
    text = SCRIPT.read_text(encoding='utf-8')
    text = BLOCK.sub(lambda m: f'{m.group(1)}{{\n{body}\n}}{m.group(2)}', text)
    SCRIPT.write_text(text, encoding='utf-8')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', nargs='+', default=[],
                        help='Engine revision hashes (keys of '
                             'flutter_engines.json)')
    parser.add_argument('--lib', action='append', default=[],
                        help='arch=path to a local unstripped libflutter.so')
    args = parser.parse_args(argv)

    table = _parse_table()
    engines = args.engine
    if not engines and not args.lib:
        # Refresh what is already in the table, mapped back to engine hashes
        known = json.loads(ENGINES.read_text())
        by_build = {}
        for engine, versions in (known.items() if isinstance(known, dict)
                                 else known):
            by_build[engine] = versions
        engines = list(by_build)

    for engine in engines:
        for arch, arch_dir in ARCHES.items():
            try:
                data = _download(engine, arch_dir)
            except Exception as exp:  # noqa: BLE001
                print(f'skip {engine} {arch}: {exp}', file=sys.stderr)
                continue
            build_id, offset = _from_binary(data)
            if not build_id or not offset:
                print(f'skip {engine} {arch}: no build-id/symbol',
                      file=sys.stderr)
                continue
            table.setdefault(build_id, {})[arch] = offset
            print(f'{engine} {arch}: {build_id} -> {hex(offset)}')

    for spec in args.lib:
        arch, _, path = spec.partition('=')
        build_id, offset = _from_binary(Path(path).read_bytes())
        if build_id and offset:
            table.setdefault(build_id, {})[arch] = offset
            print(f'{path} {arch}: {build_id} -> {hex(offset)}')

    _write_table(table)
    print(f'Wrote {len(table)} build-ids to {SCRIPT}')


if __name__ == '__main__':
    main()
