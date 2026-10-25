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
| Upstream contribution | 2 | 6 | 🟡 |
| Phase 1 — Detection & strings | 0 | 9 | 🟡 |
| Phase 2 — Snapshot, checks, CLI | 0 | 11 | ⬜ |
| Phase 3 — Source ZIP | 0 | 4 | ⬜ |
| Phase 4 — Dynamic (Android) | 0 | 4 | ⬜ |
| Phase 5 — Diff, iOS, hardening | 0 | 1 | ⬜ |
| Non-functional | 0 | 6 | ⬜ |

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
| U2 | Small focused PRs from `upstream/master` | 🟡 | 2026-10-25 | MobSF#2721 (env flags) closed by maintainer, superseded by his broader MobSF#2724 (merged 2026-10-24, same `env.py`/`env_flag()` approach, only `1` enables). Next upstream PR: Flutter step 1 after #2722 answers |
| U3 | Follow CONTRIBUTING, PR template, CLAUDE.md | 🟡 | 2026-10-23 | #2721 uses PR template; lint + tests pass. Security-relevant fixes: decide public PR vs private advisory (SECURITY.md) before pushing to fork |
| U4 | GPL-3.0-compatible dependencies only | ✅ | 2026-10-23 | blutter MIT ✅, reFlutter GPL-3.0 ✅, darter AGPL-3.0 ⚠️ (allowed via GPLv3 §13, network clause applies; old Dart only), Doldrums and Guardsquare flutter-re-demo have no license ❌ (reference only). Recommend blutter for F7 |
| U5 | Fork-only files kept out of upstream PRs | 🟡 | 2026-10-23 | Upstream branches cut from `upstream/master`; #2721 has no fork-only files |
| U6 | No breaking output/API/DB changes | ⬜ | | |

## Phase 1 — Detection, fingerprinting, strings, reporting

| ID | Task | Status | Updated | Notes |
|---|---|---|---|---|
| F1 | Detect Flutter in APK/AAB/IPA | 🟡 | 2026-10-25 | `flutter/detect.py` on `feat/flutter-detection` (from upstream). File names only, no symlink follow. Verified on real Flutter 3.44.9 release + debug APKs. Not wired into scan/report yet (waits on #2722) |
| F2 | Debug/JIT vs release/AOT build mode | 🟡 | 2026-10-25 | `kernel_blob.bin` in `flutter_assets` → debug; AOT snapshot → release. Verified on real debug APK |
| F3 | Engine + Dart SDK version, known CVEs | 🟡 | 2026-10-25 | `flutter/snapshot.py` reads snapshot hash + features (layout from dart-lang/sdk source). Dart 3.12.2 → `ace654289f5abc240509fc941453ebc5`. TODO: hash→version table (self-built), engine version, CVEs |
| F4 | Obfuscation / split-debug-info detection | ⬜ | | |
| F5 | Every `libapp.so` across ABIs and splits | 🟡 | 2026-10-25 | All ABIs + `split_apks/*` covered in `detect.py`; real APK shows 3 ABIs |
| F6 | String extraction → secrets, URLs, configs | ⬜ | | |
| F9 | `flutter_assets/` audit | ⬜ | | |
| F26 | Flutter section in HTML/PDF/JSON report | ⬜ | | |
| F27 | REST API parity | ⬜ | | |

## Phase 2 — Dart snapshot analysis, Flutter checks, CLI

| ID | Task | Status | Updated | Notes |
|---|---|---|---|---|
| F7 | Symbol / object-pool recovery | ❓ | 2026-10-23 | Parser choice per U4: blutter recommended (arm64, per-Dart-version build → N2 cache) |
| F8 | Pub package inventory | ⬜ | | Depends on F7 |
| F10 | Insecure storage | ⬜ | | |
| F11 | TLS / pinning checks | ⬜ | | |
| F12 | Platform-channel enumeration | ⬜ | | |
| F13 | WebView plugin checks | ⬜ | | |
| F14 | Root/jailbreak/tamper detection presence | ⬜ | | |
| F15 | Deep links vs manifest/plist | ⬜ | | |
| F16 | Sensitive logging | ⬜ | | |
| F17 | MASVS v2 + CWE mapping | ⬜ | | |
| F29 | CLI + SARIF output | ⬜ | | From Q6 |

## Phase 3 — Source-ZIP flow

| ID | Task | Status | Updated | Notes |
|---|---|---|---|---|
| F18 | Accept Flutter project ZIP | ⬜ | | |
| F19 | `pubspec.lock` OSV audit | ⬜ | | |
| F20 | Dart SAST rules | ⬜ | | |
| F21 | Native shell via existing MobSF rules | ⬜ | | |

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
| N5 | Test corpus ≥ 10 Flutter apps in CI | ⬜ | | |
| N6 | `tox -e lint` clean + unit tests | ⬜ | | |

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
