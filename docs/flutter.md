# Flutter analysis (this fork)

Flutter-specific analysis on top of MobSF. Code: `mobsf/StaticAnalyzer/views/flutter/`.
Plan and status: [`requirements.md`](../requirements.md), [`progress.md`](../progress.md).

## What it reports

**APK / AAB / XAPK / APKS / IPA**
- Flutter detected, every ABI and split APK
- Build mode: debug (ships `kernel_blob.bin`, Dart code recoverable: high), profile, release
- Exact Flutter version (engine revision in `libflutter.so` or `Flutter.framework/Info.plist`)
  and Dart version (the one that Flutter version ships; else the range of the snapshot hash)
- Dart SDK security advisories that affect built apps, by version
- Obfuscation (`--obfuscate`) and split debug info (`--split-debug-info`)
- Plugin and package inventory, also for obfuscated apps (from native plugin registration)
- Platform channels (list, no findings), also for obfuscated apps: plugin channels
  (name matches a detected package), app channels (name in both the Dart code and the
  app's native code: dex, iOS executable), Pigeon channels counted per package.
  Unattributed channel-like text and Flutter engine channels are left out
- Package-based checks: unencrypted storage, SSL pinning, WebView, root/jailbreak detection
- Flutter deep linking enabled, WebView JavaScript channels
- Sensitive files in `flutter_assets/` (`.env`, Firebase configs, keys, databases) and
  secrets inside them

**Flutter project ZIPs**
- `pubspec.lock` packages with exact versions
- Dart code rules (e.g. `badCertificateCallback` returning true, a token or password
  logged with `print`/`debugPrint`), with file and line
- Deep linking flags, declared assets and their secrets
- Platform channels named in `MethodChannel`, `EventChannel`, `BasicMessageChannel`
  calls, with files and the native handler files in `android/` and `ios/`
- iOS app (`ios/`): MobSF's offline iOS project-ZIP checks on the app's own code
  (CocoaPods, plugin sources and generated files skipped): Swift/Objective-C rules,
  iOS API rules, URLs and emails, hardcoded secrets (code strings and plists), and
  `ios/Runner/Info.plist` (permissions, App Transport Security, URL schemes). High and
  warning items are also Flutter findings (`flutter_ios_*`). MobSF's network checks
  (domain malware check, App Store lookup) are not repeated. `android/` gets MobSF's
  normal Android source analysis
- Optional: known vulnerabilities of locked packages from OSV (see below)

## Where it shows

- Web report: **Flutter** entry in the sidebar (Android binary/source, iOS binary reports)
- PDF report: Flutter section
- REST API: `flutter` key in `/api/v1/scan` and `/api/v1/report_json`
- Stored per scan in `~/.MobSF/scan_state/<md5>/flutter.json`; deleted with the scan

## Settings

| Variable | Default | Purpose |
|---|---|---|
| `MOBSF_FLUTTER_OSV_ENABLED` | `0` | `1` looks up `pubspec.lock` packages on api.osv.dev. **Sends dependency names and versions to a third party.** Uses MobSF's upstream proxy settings. |

## Command line

```
python manage.py flutter_scan <file-or-folder> [options]
```

| Option | Meaning |
|---|---|
| `--format json\|sarif` | Output format (default `json`) |
| `--output FILE` | Write to a file instead of stdout |
| `--fail-on high\|warning\|info` | Exit with code 1 if a finding of that severity or higher exists |
| `--osv` | OSV lookup for `pubspec.lock` (sends package names and versions) |

Input: an APK/AAB/XAPK/IPA/ZIP file or a folder (Flutter project or extracted app).

```
python manage.py flutter_scan app.apk
python manage.py flutter_scan app.ipa --format sarif --output flutter.sarif
python manage.py flutter_scan ./my_flutter_project --fail-on high
```

SARIF output is SARIF 2.1.0 with CWE and MASVS tags and GitHub `security-severity`.
**Secret values are masked** (`"API_KEY" : "abc1****"`) so uploads to code scanning
don't spread them.

### Comparing two versions

```
python manage.py flutter_diff <old> <new> [options]
```

Each side is an APK/AAB/XAPK/IPA/ZIP file or folder (scanned), a `flutter_scan` JSON,
or a MobSF report JSON (`/api/v1/report_json`; its `flutter` part is used). The output
lists Flutter/Dart version, build mode and obfuscation changes; new, fixed and
severity-changed findings; Dart rules with new hits (new files only, line moves are
ignored); added, removed and updated packages; new secrets in assets (masked).

| Option | Meaning |
|---|---|
| `--format text\|json` | Output format (default `text`) |
| `--output FILE` | Write to a file instead of stdout |
| `--fail-on-new high\|warning\|info` | Exit with code 1 if the new version adds a finding (or raises a severity) to that level or higher. A new secret in assets counts as `warning` |
| `--osv` | OSV lookup when scanning a project (sends package names and versions) |

```
python manage.py flutter_diff app-1.0.apk app-1.1.apk
python manage.py flutter_diff old_report.json new_report.json --fail-on-new high
```

Package lists of obfuscated builds come only from native plugin registration, so
comparing an obfuscated with a non-obfuscated build shows Dart-only packages as removed.

## Dynamic analysis

Scripts for the dynamic analyzer live in
`mobsf/DynamicAnalyzer/tools/frida_scripts/flutter/`.

- **TLS bypass (F22)** — `ssl-bypass-flutter.js`. Flutter uses its own BoringSSL
  in `libflutter.so` and ignores the system proxy and CA store, so HTTPS traffic
  is not visible to a MITM proxy by default. The script neutralises the engine's
  certificate check. The check has no symbol and moves every build, so the engine
  is matched by its GNU build-id and the offset is taken from a table (fallback: a
  byte-pattern scan). Regenerate the table with
  `scripts/update_flutter_frida_offsets.py`. Run on a rooted device/emulator and
  pair with a transparent proxy.

### Capturing Flutter HTTPS (F22)

`scripts/flutter_mitm.py` wires a rooted device/emulator's traffic into a
host MITM proxy and runs the bypass. The bypass makes the app accept the
proxy's certificate, so no CA has to be installed on the device.

```
# 1. start the proxy on the host (single-host target shown)
mitmdump --mode reverse:https://api.example.com:443 -p 8080

# 2. route the device's 443/80 into it (adb reverse + iptables DNAT)
python scripts/flutter_mitm.py wire

# 3. launch the app with the TLS bypass; watch decrypted traffic in mitmproxy
python scripts/flutter_mitm.py hook com.example.app

# 4. restore the device
python scripts/flutter_mitm.py unwire
```

Proxy mode notes:

- `mitmdump --mode transparent` cannot recover the original destination from a
  device-side DNAT on macOS. Use **reverse** mode for a single target host, or
  **`--mode wireguard`** (with a WireGuard client on the device) for arbitrary
  hosts. On a Linux host, classic transparent mode with TPROXY also works.
- Traffic reaches the host proxy over `adb reverse` (device `127.0.0.1:<port>` →
  host), which sidesteps emulator NIC/routing quirks; the script enables
  `route_localnet` so the DNAT to loopback is allowed.

Verified on an Android 13 emulator against a Flutter 3.44.9 release build: with
the bypass, the app's `GET https://.../` is decrypted by mitmproxy; without it,
the app aborts the handshake and only a TLS ClientHello reaches the proxy.

This is a manual analyst tool — it is not imported by MobSF's scan or dynamic
analyzer and does not change their behaviour.

## Version tables

`dart_versions.json` (snapshot hash → Dart/Flutter versions),
`flutter_engines.json` (engine revision → Flutter versions) and `flutter_dart.json`
(Flutter version → Dart version) are generated from the official Dart SDK archive and
Flutter releases:

```
python scripts/update_flutter_dart_versions.py          # add new releases
python scripts/update_flutter_dart_versions.py --all    # rebuild
```

## Limits

- Dart versions before 2.14 (Flutter before 2.5) are not in the version table.
- Obfuscated apps keep no Dart names: the package list then comes only from native
  plugin registration, and checks based on Dart names (e.g. JS channels) can't run.
- WebView JavaScript channels can't be detected in apps using `webview_flutter`
  2.x/3.x: the plugin always contains the method name, used or not.
- A Flutter project ZIP gives one report (Android source). The iOS app is shown in its
  Flutter section and does not count in MobSF's security score; for a full iOS report,
  ZIP only `ios/` and upload it.
- Platform channels: debug builds (no compiled Dart) get no list; Pigeon names of old
  plugins (no package in the name, before 2023) and app channels whose native side is
  outside the dex files / iOS main executable (e.g. in an SDK framework) are not listed.
