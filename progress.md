# Flutter Security Framework — Progress

Tracks every item in [`requirements.md`](requirements.md). Update the status,
date and notes as work lands. Last updated: 2026-10-25

**Legend:** ✅ done · 🟡 in progress · ⬜ not started · ⛔ blocked · ❓ needs decision

## Summary

| Area | Done | Total | Status |
|---|---|---|---|
| Planning | 2 | 2 | ✅ |
| Decisions | 6 | 6 | ✅ |
| Phase 0 — Git setup | 8 | 8 | ✅ |
| Phase 0 — Services & credentials | 1 | 3 | 🟡 |
| Upstream contribution | 3 | 6 | 🟡 |
| Phase 1 — Detection & strings | 9 | 9 | ✅ |
| Phase 2 — Snapshot, checks, CLI | 5 | 11 | 🟡 |
| Phase 3 — Source ZIP | 2 | 4 | 🟡 |
| Phase 4 — Dynamic (Android) | 0 | 4 | ⬜ |
| Phase 5 — Diff, iOS, hardening | 0 | 1 | ⬜ |
| False-positive reduction | 0 | 6 | 🟡 |
| Non-functional | 0 | 6 | 🟡 |

---

## Planning

| ID | Task | Status | Updated | Notes |
|---|---|---|---|---|
| P-1 | Draft `requirements.md` | ✅ | 2026-10-23 | v0.1 |
| P-2 | Record decisions in requirements | ✅ | 2026-10-23 | v0.2 |

## Decisions

| ID | Question | Status | Answer |
|---|---|---|---|
| Q1 | Distribution model / GPL-3.0 | ✅ | Reuse MobSF, open source GPL-3.0, upstream later |
| Q2 | Repo location and visibility | ✅ | Keep current public fork |
| Q3 | Platform priority | ✅ | Android first, iOS after |
| Q4 | Third-party snapshot parsers | ✅ | Allowed if GPL-3.0-compatible (U4) |
| Q5 | Dynamic lab | ✅ | Emulators first, physical devices/Corellium later |
| Q6 | Target users | ✅ | Both → CLI + SARIF (F29) |

## Phase 0 — Git setup

| ID | Task | Status | Updated | Notes |
|---|---|---|---|---|
| G1 | `origin` = our fork | ✅ | 2026-10-23 | `captainrogers69/Mobile-Security-Framework-MobSF` |
| G2 | `upstream` remote and merge cadence | ✅ | 2026-10-23 | Weekly (Mon 03:00 UTC) via `.github/workflows/upstream-sync.yml` → opens PR `sync/upstream` → `master`. `SYNC_TOKEN` set; manual run passed ("Already up to date"). PR-opening path untested until upstream moves |
| G3 | Branching model and `master` protection | ✅ | 2026-10-23 | `feat/flutter-*` branches. `master`: PR required (0 approvals), checks `build (ubuntu-22.04, 3.12/3.13)` + `buildx`, up-to-date branch, conversations resolved, no force-push/delete, admin bypass on for upstream syncs |
| G7 | Issues enabled on fork | ✅ | 2026-10-23 | |
| G8 | `.github/CODEOWNERS` → `@captainrogers69` | ✅ | 2026-10-23 | Committed (44752454). Fork-only (U5) |
| G4 | Isolated Flutter package layout | ✅ | 2026-10-23 | `mobsf/StaticAnalyzer/views/flutter/`, `mobsf/DynamicAnalyzer/tools/frida_scripts/flutter/` (empty scaffolds) |
| G5 | CI: lint, tests, Docker build on PR | ✅ | 2026-10-23 | `MobSF tests` (ubuntu/macos/windows × 3.12/3.13) + `buildx` green on PR #1 and on `master` after merge. Publish workflows disabled. CodeQL off (GitHub disables it on forks) |
| G6 | Repo visibility | ✅ | 2026-10-23 | Public fork |

## Phase 0 — Services & credentials

| ID | Task | Status | Updated | Notes |
|---|---|---|---|---|
| S1 | `.env` + CI secrets, gitleaks in CI | 🟡 | 2026-10-23 | `.env` gitignored, `.env.example` added, `.github/workflows/secret-scan.yml` (gitleaks 8.21.2, sha256-pinned, scans new commits only; upstream history has 33 old findings). Passing on PRs. TODO: add `gitleaks` to required checks on `master` |
| S2 | Credentials inventory provisioned | ✅ | 2026-10-25 | GitHub PAT `SYNC_TOKEN` (90-day expiry). Local `.env` with `MOBSF_SECRET_KEY`, SQLite. VT off. OSV no key. Registry deferred to first release (GHCR planned). Lab: AVD `MobSF_API30` (Android 11, API 30 = MobSF max, Google APIs arm64-v8a), `/system` writable, `127.0.0.1:5555` |
| S3 | `MOBSF_*` env vars documented | ✅ | 2026-10-23 | `docs/environment.md`: every var MobSF reads, defaults, and parse rule (`bool(getenv)` flags like `MOBSF_VT_UPLOAD` are on for `0`). Upstream PR candidate |

## Upstream contribution

| ID | Task | Status | Updated | Notes |
|---|---|---|---|---|
| U1 | Feature-request issue upstream | ✅ | 2026-10-23 | MobSF#2722, assigned `ajinabraham`. Asks: core fit, external parser (blutter) OK, report section vs folded, code layout. Wait for answers before first Flutter PR |
| U2 | Small focused PRs from `upstream/master` | ✅ | 2026-10-26 | First merged: MobSF#2730 (Dart strings from `libapp.so`), approved and merged by `ajinabraham` 2026-10-25, all 13 CI checks green (Linux/macOS/Windows). He merged master in and dropped our `tests_elf.py`, kept `elf.py` as written. Earlier: #2721 superseded by his #2724 |
| U3 | Follow CONTRIBUTING, PR template, CLAUDE.md | 🟡 | 2026-10-23 | #2721 uses PR template; lint + tests pass. Security-relevant fixes: decide public PR vs private advisory (SECURITY.md) before pushing to fork |
| U4 | GPL-3.0-compatible dependencies only | ✅ | 2026-10-23 | blutter MIT ✅, reFlutter GPL-3.0 ✅, darter AGPL-3.0 ⚠️ (allowed via GPLv3 §13, network clause applies; old Dart only), Doldrums and Guardsquare flutter-re-demo have no license ❌ (reference only). Recommend blutter for F7 |
| U5 | Fork-only files kept out of upstream PRs | 🟡 | 2026-10-23 | Upstream branches cut from `upstream/master`; #2721 has no fork-only files |
| U6 | No breaking output/API/DB changes | ⬜ | | |

## Phase 1 — Detection, fingerprinting, strings, reporting

| ID | Task | Status | Updated | Notes |
|---|---|---|---|---|
| F1 | Detect Flutter in APK/AAB/IPA | ✅ | 2026-10-26 | `flutter/detect.py` (names only, no symlink follow). Verified on real Flutter 3.44.9 Android release/debug APKs and iOS release builds. Report wiring under F26 |
| F2 | Debug/JIT vs release/AOT build mode | ✅ | 2026-10-26 | Android: `kernel_blob.bin` → debug, AOT snapshot → release. iOS: `BuildMode` in `Flutter.framework/Info.plist` (debug/profile/release) |
| F3 | Engine + Dart SDK version, known CVEs | ✅ | 2026-10-26 | Dart range from snapshot hash (`dart_versions.json`, 24 hashes, Dart 2.14–3.13.7). Exact Flutter version from engine revision (`flutter_engines.json`, 149 revs / 173 versions): Android `libflutter.so`, iOS `Flutter.framework/Info.plist`. Both tables from `scripts/update_flutter_dart_versions.py`. `dart_advisories.json`: 3 runtime advisories from dart-lang/sdk (GHSA-frr6-h895-5pxp TLS MitM Android, CVE-2022-3095, CVE-2022-0451), affected / possibly affected |
| F4 | Obfuscation / split-debug-info detection | ✅ | 2026-10-26 | `flutter/obfuscation.py`: `dwarf_stack_traces_mode` feature → split-debug-info; distinct `package:` URIs < 20 → obfuscated (~300 plain vs 3 obfuscated). Verified on 5 real builds (Android plain/split/obfuscated, iOS plain/obfuscated) |
| F5 | Every `libapp.so` across ABIs and splits | ✅ | 2026-10-26 | All ABIs + `split_apks/*` in `detect.py`; real APK shows 3 ABIs |
| F6 | String extraction → secrets, URLs, configs | ✅ | 2026-10-26 | `ELFChecksec.strings()` missed all Dart strings in `libapp.so` (lief returns C strings only). Fixed upstream in MobSF#2730 (merged): strings 27 → 12342, hardcoded secrets/URLs now go through MobSF's existing secret/URL/Firebase checks; `libflutter.so` unchanged. iOS already used `strings_on_binary()` |
| F9 | `flutter_assets/` audit | ✅ | 2026-10-26 | `flutter/assets.py`: flags `.env`, Firebase configs, keys, DBs, named configs; scans text assets for secrets with MobSF's `is_secret_key` + `detect_known_secrets`. Verified on real APK with bundled `.env` |
| F26 | Flutter section in HTML/PDF/JSON report | ✅ | 2026-10-26 | Fork: `feat/flutter-integration` (PR #10). Nav entry + section in Android binary/source and iOS binary reports, PDF section, JSON report API. Result stored as `scan_state/<md5>/flutter.json` (no DB change). Upstream layout still to agree in #2722 |
| F27 | REST API parity | ✅ | 2026-10-26 | `/api/v1/scan` and `/api/v1/report_json` return `flutter`; verified end to end on an isolated instance |

## False-positive reduction (from MobSF#2722 feedback)

Before/after numbers are measured on the real Flutter test APK (no real secrets).

| ID | Task | Status | Updated | Notes |
|---|---|---|---|---|
| F30 | Skip `io/flutter/` in code analysis | 🟡 | 2026-10-26 | Upstream PR MobSF#2736 open (1 line in `SKIP_CLASS_PATH`). Flutter APK code hits 76 → 61, non-Flutter sample unchanged |
| F31 | No secrets/URLs from `libflutter.so` | 🟡 | 2026-10-26 | Upstream PR MobSF#2737 open (with F32): engine (`libflutter.so`, `Flutter.framework/Flutter`) reports only known-format secrets, Android + iOS paths. APK secrets 12 → 5, IPA 26 → 21, non-Flutter unchanged |
| F32 | Drop known Flutter identifiers from secrets | 🟡 | 2026-10-26 | In MobSF#2737: snapshot hash skipped where it appears as the snapshot header. Build-path IDs left out (test-environment artifact) |
| F33 | Ignore fixed plugin constants | 🟡 | 2026-10-26 | Built, queued (`upstream-prs/queue/02`, branch `fix/flutter-plugin-constants`): exact `flutter_secure_storage` / `shared_preferences` base64 constants skipped (plugin code is R8-minified, so path skips don't work). APK 12 → 8 alone, 12 → 1 with #2737 |
| F34 | Native libs analysed twice (`apktool_out/`) | 🟡 | 2026-10-26 | Cause: apktool copies `lib/` to `apktool_out/`, `library_analysis()` globs the whole upload dir. Built, queued (`upstream-prs/queue/04`, branch `fix/skip-apktool-copies`): MobSF sample APK 14 → 7 entries, Flutter APK 16 → 8. Same bug fixed in the fork's Flutter walk (PR #15, merged) |
| F35 | Swift private symbol hashes reported as secrets | 🟡 | 2026-10-26 | Built, queued (`upstream-prs/queue/03`, branch `fix/swift-symbol-secrets`): Swift symbol names skipped before the entropy check. IPA 26 → 6 alone; with #2737 + queue 02: APK 12 → 1, IPA 26 → 1. Conflicts with queue 02 (resolution tested) |

## Phase 2 — Dart snapshot analysis, Flutter checks, CLI

| ID | Task | Status | Updated | Notes |
|---|---|---|---|---|
| F7 | Symbol / object-pool recovery | ❓ | 2026-10-23 | Parser choice per U4: blutter recommended (arm64, per-Dart-version build → N2 cache) |
| F8 | Pub package inventory | 🟡 | 2026-10-26 | Names from Dart `package:` URIs (non-obfuscated) + native plugin inventory `flutter/plugins.py` (Android `GeneratedPluginRegistrant` strings in dex, iOS Swift mangled plugin classes / CocoaPods frameworks; works on obfuscated apps). Versions need F7 or `pubspec.lock` (F19) |
| F10 | Insecure storage | ✅ | 2026-10-26 | Package level (`checks.py`) + Dart rule `dart_prefs_sensitive` (sensitive keys in SharedPreferences, warning) |
| F11 | TLS / pinning checks | ✅ | 2026-10-26 | Package level + Dart rules: `badCertificateCallback` returning true (high), `HttpOverrides.global` (info), `SecurityContext` pinning (good). Binary: callback leaves no trace, source only |
| F12 | Platform-channel enumeration | ⬜ | | |
| F13 | WebView plugin checks | ✅ | 2026-10-26 | Package level; binary: `addJavaScriptChannel` name (non-obfuscated); Dart rules: unrestricted JS (warning), JS channels/handlers (info) |
| F14 | Root/jailbreak/tamper detection presence | ✅ | 2026-10-26 | Package level: detection package good / absent info (resilience-1). Package names verified on pub.dev |
| F15 | Deep links vs manifest/plist | ✅ | 2026-10-26 | `deeplinks.py`: `flutter_deeplinking_enabled` (manifest) / `FlutterDeepLinkingEnabled` (Info.plist) → info (cwe-939, platform-1), APK/IPA and project ZIP |
| F16 | Sensitive logging | 🟡 | 2026-10-26 | Dart rule `dart_logging` (print/debugPrint, info). No binary-level check |
| F17 | MASVS v2 + CWE mapping | ✅ | 2026-10-26 | Every Flutter finding has a MASVS v2 category and, where one applies, a CWE (none on "good" findings or on Dart advisories without a published CWE). Shown in report and API, SARIF tags |
| F29 | CLI + SARIF output | ✅ | 2026-10-26 | `manage.py flutter_scan` (`--format json\|sarif`, `--output`, `--fail-on`, `--osv`), SARIF 2.1.0 with masked secrets. See `docs/flutter.md` |

## Phase 3 — Source-ZIP flow

| ID | Task | Status | Updated | Notes |
|---|---|---|---|---|
| F18 | Accept Flutter project ZIP | ✅ | 2026-10-26 | Fixed MobSF bug: Flutter ZIPs could not be scanned (root: `.gitignore` collision on move; wrapped: rejected). `move_flutter_android()` + `scan_source()` before the source check. Upstream PR candidate |
| F19 | `pubspec.lock` OSV audit | ✅ | 2026-10-26 | Wired behind `MOBSF_FLUTTER_OSV_ENABLED` (default `0`, opt-in: sends dependency names to osv.dev) |
| F20 | Dart SAST rules | ✅ | 2026-10-26 | `rules/dart_rules.yaml`, 13 rules via MobSF `SastEngine`; positive+negative fixtures; Flutter framework lib (694 files): no high false positives |
| F21 | Native shell via existing MobSF rules | 🟡 | 2026-10-26 | Works today through MobSF's relaxed Android source check on `android/`; iOS shell not analysed for Flutter ZIPs |

## Phase 4 — Dynamic analysis (Android)

| ID | Task | Status | Updated | Notes |
|---|---|---|---|---|
| F22 | Flutter TLS bypass + transparent proxy | ⬜ | | Emulators first (Q5) |
| F23 | Platform-channel tracing | ⬜ | | |
| F24 | Runtime storage dump | ⬜ | | |
| F25 | iOS dynamic behind flag | ⬜ | | After Android (Q3) |

## Phase 5 — Diff, iOS parity, hardening

| ID | Task | Status | Updated | Notes |
|---|---|---|---|---|
| F28 | Scan comparison between versions | ⬜ | | |

## Non-functional (ongoing)

| ID | Task | Status | Updated | Notes |
|---|---|---|---|---|
| N1 | Sandboxed external parsers, list args, timeouts | ⬜ | | |
| N2 | Parser build cache + graceful failure | ⬜ | | |
| N3 | ≤ 2 min added per 50 MB APK | ⬜ | | |
| N4 | Tools baked into Docker image | ⬜ | | |
| N5 | Test corpus ≥ 10 Flutter apps in CI | 🟡 | 2026-10-26 | 32 apps: 8 builds of 3 ordinary apps (template, plugins, http; Android release/debug/obfuscated, iOS release) with Flutter 3.44.9, 3.27.4, 3.10.6, 3.0.5 (Dart 3.12 to 2.17). `scripts/flutter_corpus/build.sh`, `fetch_sdk.sh`, `scripts/flutter_corpus_check.py` with expected results; 32/32 match. Found and fixed a false positive: JS channel reported for every webview_flutter 3.x app. To do: run in CI once Actions is back |
| N6 | `tox -e lint` clean + unit tests | ✅ | 2026-10-26 | Lint clean on every PR; 173 Flutter unit tests. Locally 2 integration tests need missing tools (wkhtmltopdf, x86 class-dump), same on upstream master |

---

## Log

| Date | Change |
|---|---|
| 2026-10-23 | Created `requirements.md` v0.1 and `progress.md` |
| 2026-10-23 | Recorded Q1–Q6 decisions, added upstream contribution section (U1–U6) and F29 |
| 2026-10-23 | `upstream` remote fetched; branch `feat/flutter-planning` created |
| 2026-10-23 | Planning docs committed (72fd4cb6, not pushed); `master` protected; Issues on; CODEOWNERS added |
| 2026-10-23 | PR #1 merged, CI green (G5). Secret scan + upstream sync + Flutter package scaffolds (G4) on `feat/flutter-ci-secrets` (PR #2). U4 license review done. S3 env docs; fixed `.env.example` VT flags (`0` enabled VT upload) |
| 2026-10-23 | Q5 confirmed; weekly upstream sync workflow; S1 secret handling + gitleaks workflow |
| 2026-10-23 | PR #2 merged. Upstream sync tested. Opened MobSF#2721 (env flag parsing, first upstream PR) and feature request MobSF#2722 (U1) |
| 2026-10-25 | S2 done: `.env` set up, Android 11 emulator verified for dynamic analysis. Phase 0 complete |
| 2026-10-25 | Upstream fixed env flags in MobSF#2724 (supersedes our #2721). TODO after next upstream sync: update `docs/environment.md` parse rules (only `1` enables) |
| 2026-10-25 | GitHub disabled Actions on the fork (ticket to GitHub Support pending). PR #6 merged: fork CI runs Linux-only test matrix and amd64-only Docker test. PR #5 merged via admin bypass |
| 2026-10-25 | Flutter F1/F2/F3/F5 core logic on `feat/flutter-detection` (60be2628, 1ad840b8): 25 unit tests, verified on real APKs. Upstream push URL set to `no_push` locally |
| 2026-10-25 | Dart version table (619e42cd, af6867f0), F9 asset audit + secret scan (14430672, 6a6e6b1a), F6 Dart strings fix in `elf.py` (a5991e7b). 54 Flutter tests |
| 2026-10-26 | MobSF#2730 merged upstream (first merged contribution): F6 ✅, U2 ✅. Branch `fix/elf-dart-strings` deleted |
| 2026-10-26 | F3 completed (engine version Android + iOS, Dart advisories), F4 obfuscation/split-debug-info. Phase 1 analysis logic done (F1–F6, F9); report wiring (F26/F27) waits on MobSF#2722. Next: post #2722 follow-up (2026-10-27) |
| 2026-10-26 | Plugin inventory from native code (1222a62d) and package-based checks F10/F11/F13/F14 (5199cb48); identical findings on Android, obfuscated Android and iOS builds. 103 Flutter tests |
| 2026-10-26 | Binary deep-link + JS channel checks (b9e6b32b); source ZIP pieces: project detection + pubspec.lock (1d3fe39f), OSV (99bfed64), Dart rules (69393baf); entry points `flutter_binary_analysis` (ea141720) and `flutter_source_analysis` (cd493508). 142 Flutter tests, full suite 177 (same 2 local integration failures) |
| 2026-10-26 | Flutter analysis wired into the fork's MobSF (3a6c48f2, f403035e; PR #10): scans, web/PDF reports, JSON API; Flutter project ZIPs now scannable. E2E verified on isolated instance; full suite 190 tests (2 known local failures) |
| 2026-10-26 | Maintainer replied on #2722 (small iterative PRs, no third-party binaries, fewer false positives). Measured false positives on a real Flutter APK; added F30–F34. #2722 follow-up posted with small-PR plan. Upstream PR #2734 (Flutter source ZIPs) open |
| 2026-10-26 | F30 upstream PR #2736 opened; F31/F32 built and queued; F35 added. Upstream PR drafts and logs kept in local `upstream-prs/` (gitignored). Manual upstream sync PR #13 |
| 2026-10-26 | Upstream PR #2737 opened (F31/F32); 3 upstream PRs open (#2734, #2736, #2737). F33, F34, F35 built and queued. Fork PR #15 merged (Flutter walk skips MobSF output folders) |
| 2026-10-26 | Done the TODO from MobSF#2724: `docs/environment.md` and `.env.example` now state the single flag rule (only `1` enables; env wins over `config.py`). Added `MOBSF_FLUTTER_OSV_ENABLED` and `docs/flutter.md` (features, CLI, settings, limits) |
| 2026-10-26 | N5 started: Flutter corpus regression check (8 apps). CLI no longer logs scan-database errors |
| 2026-10-26 | N5: corpus with 4 Flutter versions (32 apps). JS channel check no longer flags every webview_flutter 2.x/3.x app |
