#!/bin/bash
# Download an official Flutter SDK (macOS) and verify its sha256.
# Usage: fetch_sdk.sh VERSION DEST_DIR   -> DEST_DIR/flutter-VERSION/bin/flutter
set -eu
VER=$1; DEST=$2
ARCH=$([ "$(uname -m)" = arm64 ] && echo arm64 || echo x64)
BASE=https://storage.googleapis.com/flutter_infra_release/releases
read -r ARCHIVE SHA < <(curl -sSfL "$BASE/releases_macos.json" | python3 -c "
import json, sys
d = json.load(sys.stdin)
r = [x for x in d['releases'] if x['channel'] == 'stable' and x['version'] == '$VER' and x.get('dart_sdk_arch') == '$ARCH']
print(r[0]['archive'], r[0]['sha256'])")
mkdir -p "$DEST"; ZIP="$DEST/flutter-$VER.zip"
curl -sSfL -o "$ZIP" "$BASE/$ARCHIVE"
GOT=$(shasum -a 256 "$ZIP" | awk '{print $1}')
[ "$GOT" = "$SHA" ] || { echo "sha256 mismatch for $VER"; rm -f "$ZIP"; exit 1; }
rm -rf "$DEST/flutter-$VER" "$DEST/flutter"
(cd "$DEST" && unzip -q "$ZIP" && mv flutter "flutter-$VER")
rm -f "$ZIP"
echo "$DEST/flutter-$VER/bin/flutter"
