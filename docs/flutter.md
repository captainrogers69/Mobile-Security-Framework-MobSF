# Flutter analysis (this fork)

Flutter-specific analysis on top of MobSF. Code: `mobsf/StaticAnalyzer/views/flutter/`.
Plan and status: [`requirements.md`](../requirements.md), [`progress.md`](../progress.md).

## What it reports

**APK / AAB / XAPK / APKS / IPA**
- Flutter detected, every ABI and split APK
- Build mode: debug (ships `kernel_blob.bin`, Dart code recoverable: high), profile, release
- Exact Flutter version (engine revision in `libflutter.so` or `Flutter.framework/Info.plist`)
  and Dart version (snapshot hash)
- Dart SDK security advisories that affect built apps, by version
- Obfuscation (`--obfuscate`) and split debug info (`--split-debug-info`)
- Plugin and package inventory, also for obfuscated apps (from native plugin registration)
- Package-based checks: unencrypted storage, SSL pinning, WebView, root/jailbreak detection
- Flutter deep linking enabled, WebView JavaScript channels
- Sensitive files in `flutter_assets/` (`.env`, Firebase configs, keys, databases) and
  secrets inside them

**Flutter project ZIPs**
- `pubspec.lock` packages with exact versions
- Dart code rules (e.g. `badCertificateCallback` returning true), with file and line
- Deep linking flags, declared assets and their secrets
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

## Version tables

`dart_versions.json` (snapshot hash → Dart/Flutter versions) and
`flutter_engines.json` (engine revision → Flutter versions) are generated from the
official Dart SDK archive and Flutter releases:

```
python scripts/update_flutter_dart_versions.py          # add new releases
python scripts/update_flutter_dart_versions.py --all    # rebuild
```

## Limits

- Dart versions before 2.14 (Flutter before 2.5) are not in the version table.
- Obfuscated apps keep no Dart names: the package list then comes only from native
  plugin registration, and checks based on Dart names (e.g. JS channels) can't run.
- For Flutter project ZIPs, only the Android app in `android/` goes through MobSF's
  Android source analysis; the iOS app in `ios/` is not analysed yet.
