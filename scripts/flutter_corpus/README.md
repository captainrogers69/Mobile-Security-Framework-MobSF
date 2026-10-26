# Flutter corpus

Regression check for the Flutter analysis on real apps. The apps are not in the
repository (binaries); `build.sh` recreates them, `expected/` holds the expected
results.

## Apps

Ordinary apps only, built with Flutter 3.44.9:

| App | Content | Builds |
|---|---|---|
| `template` | `flutter create` default app | Android release, debug, obfuscated; iOS release |
| `plugins` | `shared_preferences`, `flutter_secure_storage`, `webview_flutter` | Android release, obfuscated; iOS release |
| `http_demo` | `http` package, one HTTPS request | Android release (`http-release.apk`) |

## Use

```
# Build the corpus (needs Flutter and, for iOS, Xcode; apps go to apps/)
./scripts/flutter_corpus/build.sh

# Compare with the expected results (exit 1 on any difference)
python scripts/flutter_corpus_check.py <corpus>/apps

# After an intended change, review the differences, then record them
python scripts/flutter_corpus_check.py <corpus>/apps --update
```

`build.sh` creates `src/` and `apps/` next to itself; copy it to a scratch folder
first so the build output stays out of the repository.

## What is compared

Per app: platform, build mode, ABIs, Flutter and Dart versions, obfuscation, split
debug info, packages, plugins, deep linking, JS channels, sensitive assets, files
with secrets, and finding IDs with severity. Paths and descriptions are not compared.

A different Flutter SDK version changes versions and possibly findings; record a
new baseline with `--update` when the SDK changes.
