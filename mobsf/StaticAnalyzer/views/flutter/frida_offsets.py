# -*- coding: utf_8 -*-
"""Build-id to function-offset table for the Flutter TLS bypass script.

The Frida script `frida_scripts/flutter/ssl-bypass-flutter.js` hooks
BoringSSL's `ssl_verify_peer_cert` inside `libflutter.so`. That function
moves with every engine build, so the script identifies the engine by
its GNU build-id (read from the loaded ELF) and looks up the offset in a
table embedded in the script. This module parses that table, so the
generator (`scripts/update_flutter_frida_offsets.py`) and the tests read
it the same way.
"""
import json
import re
from pathlib import Path

# Mangled BoringSSL symbol: bssl::ssl_verify_peer_cert(bssl::SSL_HANDSHAKE*)
SSL_SYMBOL = '_ZN4bssl20ssl_verify_peer_certEPNS_13SSL_HANDSHAKEE'
SCRIPT = (Path(__file__).resolve().parents[3]
          / 'DynamicAnalyzer' / 'tools' / 'frida_scripts' / 'flutter'
          / 'ssl-bypass-flutter.js')
_BLOCK = re.compile(
    r'var FLUTTER_SSL_OFFSETS\s*=\s*(\{.*?\});', re.DOTALL)


def parse_offsets_block(script_text):
    """Return the build-id -> {arch: offset} table embedded in the script."""
    match = _BLOCK.search(script_text)
    if not match:
        raise ValueError('FLUTTER_SSL_OFFSETS table not found in script')
    return json.loads(match.group(1))


def load_ssl_offsets(script_path=SCRIPT):
    """Parse the offsets table from the shipped Frida script."""
    return parse_offsets_block(Path(script_path).read_text(encoding='utf-8'))
