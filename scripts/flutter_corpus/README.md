# Flutter corpus

Regression check for the Flutter analysis on real apps. The apps are not in the
repository (binaries); `build.sh` recreates them, `expected/` holds the expected
results.

## Apps

Ordinary apps only, 8 builds per Flutter version. Files are named
`f<flutter version>-<build>.<apk|ipa>`, e.g. `f3.44.9-template-release.apk`.

| Flutter | Dart | Why |
|---|---|---|
| 3.44.9 | 3.12 | current SDK |
| 3.27.4 | 3.6 | iOS plugins through CocoaPods (newer versions use Swift Package Manager) |
| 3.10.6 | 3.0 | first Dart 3 |
| 3.0.5 | 2.17 | old snapshot format, Dart advisories of 2022, webview_flutter 3.x |

32 apps in total.

| App | Content | Builds |
|---|---|---|
| `template` | `flutter create` default app | Android release, debug, obfuscated; iOS release |
| `plugins` | `shared_preferences`, `flutter_secure_storage`, `webview_flutter` | Android release, obfuscated; iOS release |
| `http_demo` | `http` package, one HTTPS request | Android release (`http-release`) |

## Use

```
# Build the corpus with the flutter on PATH (iOS needs Xcode; apps go to apps/)
./build.sh

# Build with another Flutter version: fetch the official SDK (sha256 checked)
./fetch_sdk.sh 3.27.4 sdks
./build.sh sdks/flutter-3.27.4/bin/flutter

# Compare with the expected results (exit 1 on any difference)
python scripts/flutter_corpus_check.py <corpus>/apps

# After an intended change, review the differences, then record them
python scripts/flutter_corpus_check.py <corpus>/apps --update
```

`build.sh` creates `src-<version>/` and `apps/` next to itself; copy `build.sh` and
`fetch_sdk.sh` to a scratch folder first so the build output stays out of the
repository. To keep packages and Gradle downloads out of your home folder, set
`PUB_CACHE` and `GRADLE_USER_HOME` to scratch folders. Current Xcode needs iOS 15,
so `build.sh` raises the iOS deployment target of the generated projects.

### Old Flutter versions

`build.sh` adapts the generated projects of old versions so they still build
with current tools; none of this changes the Dart or Flutter code in the apps:

- Packages: the versions that were current when that Flutter version was
  released (latest ones need newer Android tooling).
- Android: minSdk 19 for the `plugins` app on 3.10 and 3.0 (required by
  `flutter_secure_storage` and `webview_flutter`).
- iOS: deployment target 15 also for CocoaPods targets; a `File.exists?` shim
  in old Podfiles (removed in Ruby 3.2).

Requirements on Apple Silicon:

- Rosetta: Android release builds of old versions run an x86_64
  `gen_snapshot` (needed for 3.27.4 and older here; 3.44.9 builds without).
- JDK 17 for Flutter 3.27 and older (their Gradle and Android Gradle plugin do
  not run on Java 21). Set `GRADLE_JAVA_HOME`; `build.sh` writes it to each
  generated project's `gradle.properties` only, not to global settings.

```
GRADLE_JAVA_HOME=/path/to/jdk-17 PUB_CACHE=$PWD/cache/pub \
  GRADLE_USER_HOME=$PWD/cache/gradle ./build.sh sdks/flutter-3.0.5/bin/flutter
```

## What is compared

Per app: platform, build mode, ABIs, Flutter and Dart versions, obfuscation, split
debug info, packages, plugins, deep linking, JS channels, sensitive assets, files
with secrets, and finding IDs with severity. Paths and descriptions are not compared.

Each Flutter version has its own expected files. To add a version, build it,
review the new results by hand (versions, advisories, plugins), then `--update`.
