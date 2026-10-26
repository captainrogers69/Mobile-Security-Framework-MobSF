#!/bin/bash
# Build a small corpus of ordinary Flutter apps.
# Usage: build.sh [FLUTTER_BIN]   (default: flutter on PATH)
# Optional: APPS="template plugins http_demo channel_demo" builds only these.
# Optional: GRADLE_JAVA_HOME=<JDK 17> for old Flutter versions whose Gradle or
# Android Gradle plugin does not run on newer Java (set per project only).
# Apps go to apps/f<version>-<name>.<apk|ipa>.
set -u
C=$(cd "$(dirname "$0")" && pwd)
FLUTTER=${1:-flutter}
# First run of an SDK prints a welcome banner before the JSON
VER=$("$FLUTTER" --version --machine 2>/dev/null | sed -n -E 's/.*"frameworkVersion": *"([^"]+)".*/\1/p' | head -1)
[ -n "$VER" ] || { echo "cannot read Flutter version"; exit 1; }
SRC="$C/src-$VER"
mkdir -p "$SRC" "$C/apps"
cd "$SRC"
log() { echo "[$(date +%H:%M:%S)] $*"; }

mkapp() {  # name platforms
  rm -rf "$1" && "$FLUTTER" create --platforms="$2" --org com.example "$1" > "$1.create.log" 2>&1
  # Current Xcode needs iOS 15+; older templates target 9-13
  if [ -f "$1/ios/Runner.xcodeproj/project.pbxproj" ]; then
    sed -i '' -E 's/IPHONEOS_DEPLOYMENT_TARGET = ([0-9]|1[0-4])\.[0-9];/IPHONEOS_DEPLOYMENT_TARGET = 15.0;/g' "$1/ios/Runner.xcodeproj/project.pbxproj"
    [ -f "$1/ios/Podfile" ] && sed -i '' -E "s/^# *platform :ios, '[0-9.]+'/platform :ios, '15.0'/" "$1/ios/Podfile"
    [ -f "$1/ios/Flutter/AppFrameworkInfo.plist" ] && sed -i '' -E 's#<string>([0-9]|1[0-4])\.[0-9]</string>#<string>15.0</string>#' "$1/ios/Flutter/AppFrameworkInfo.plist"
  fi
  if [ -n "${GRADLE_JAVA_HOME:-}" ] && [ -f "$1/android/gradle.properties" ]; then
    echo "org.gradle.java.home=$GRADLE_JAVA_HOME" >> "$1/android/gradle.properties"
  fi
  return 0
}
# Old Flutter versions get the package versions that were current at their
# release (newer ones need newer Android/Gradle tooling). Empty: latest.
PLUGINS_PINS=""; PLUGINS_OVERRIDES=""; HTTP_PIN=""; WEBVIEW_API=4; PLUGINS_MIN_SDK=""
case "$VER" in
  3.27.*) PLUGINS_PINS="shared_preferences:2.5.2 flutter_secure_storage:9.2.4 webview_flutter:4.10.0"
          PLUGINS_OVERRIDES="shared_preferences_android:2.4.5 webview_flutter_android:4.3.2 webview_flutter_wkwebview:3.18.0"
          HTTP_PIN="http:1.3.0" ;;
  3.10.*) PLUGINS_PINS="shared_preferences:2.2.0 flutter_secure_storage:8.0.0 webview_flutter:4.2.2"
          PLUGINS_OVERRIDES="shared_preferences_android:2.2.0 shared_preferences_foundation:2.3.1 webview_flutter_android:3.8.2 webview_flutter_wkwebview:3.6.2"
          HTTP_PIN="http:1.1.0"; PLUGINS_MIN_SDK=19 ;;
  3.0.*)  PLUGINS_PINS="shared_preferences:2.0.15 flutter_secure_storage:5.0.2 webview_flutter:3.0.4"
          PLUGINS_OVERRIDES="shared_preferences_android:2.0.12 shared_preferences_ios:2.1.1 webview_flutter_android:2.8.14 webview_flutter_wkwebview:2.9.0"
          HTTP_PIN="http:0.13.4"; WEBVIEW_API=3; PLUGINS_MIN_SDK=19 ;;
esac
add_deps() {  # app "pkg:ver ..." "override-pkg:ver ..." latest-pkgs...
  local app=$1 pins=$2 overrides=$3; shift 3
  if [ -z "$pins" ]; then
    (cd "$app" && "$FLUTTER" pub add "$@" > "../$app.pub.log" 2>&1); return
  fi
  local dep lines="" olines=""
  for dep in $pins; do lines="$lines  ${dep%%:*}: ${dep#*:}\n"; done
  for dep in $overrides; do olines="$olines  ${dep%%:*}: ${dep#*:}\n"; done
  awk -v add="$lines" '{print} /^dependencies:$/{printf "%s", add}' "$app/pubspec.yaml" > "$app/pubspec.tmp" && mv "$app/pubspec.tmp" "$app/pubspec.yaml"
  [ -n "$olines" ] && printf "\ndependency_overrides:\n$olines" >> "$app/pubspec.yaml"
  (cd "$app" && "$FLUTTER" pub get > "../$app.pub.log" 2>&1)
}
podfile_target() {  # app: CocoaPods targets keep old iOS targets unless forced
  local pf="$SRC/$1/ios/Podfile"
  [ -f "$pf" ] || (cd "$SRC/$1" && "$FLUTTER" build ios --config-only --release --no-codesign > /dev/null 2>&1)
  [ -f "$pf" ] || return 0
  sed -i '' -E "s/^# *platform :ios, '[0-9.]+'/platform :ios, '15.0'/" "$pf"
  # Old Podfiles and Flutter's podhelper.rb call File.exists?, removed in Ruby 3.2
  if ! grep -q "def exists?" "$pf"; then
    printf '%s\n' 'class ::File; def self.exists?(p) exist?(p) end unless respond_to?(:exists?); end' | cat - "$pf" > "$pf.tmp" && mv "$pf.tmp" "$pf"
  fi
  grep -q "IPHONEOS_DEPLOYMENT_TARGET" "$pf" && return 0
  sed -i '' "s/^    flutter_additional_ios_build_settings(target)$/    flutter_additional_ios_build_settings(target)\\
    target.build_configurations.each { |c| c.build_settings['IPHONEOS_DEPLOYMENT_TARGET'] = '15.0' }/" "$pf"
}
apk() {  # app out-name extra-args...
  local app=$1 out=$2; shift 2
  (cd "$SRC/$app" && "$FLUTTER" build apk "$@" > "$C/apps/f$VER-$out.build.log" 2>&1) && \
    cp "$SRC/$app/build/app/outputs/flutter-apk/app-$( [[ " $* " == *" --debug "* ]] && echo debug || echo release ).apk" "$C/apps/f$VER-$out.apk" && log "built f$VER-$out.apk" || log "FAILED $out"
}
ipa() {  # app out-name extra-args...
  local app=$1 out=$2; shift 2
  podfile_target "$app"
  (cd "$SRC/$app" && "$FLUTTER" build ios --release --no-codesign "$@" > "$C/apps/f$VER-$out.build.log" 2>&1) && \
    rm -rf "$SRC/_ipa" && mkdir -p "$SRC/_ipa/Payload" && cp -R "$SRC/$app/build/ios/iphoneos/Runner.app" "$SRC/_ipa/Payload/" && \
    (cd "$SRC/_ipa" && rm -f "$C/apps/f$VER-$out.ipa" && zip -qr "$C/apps/f$VER-$out.ipa" Payload) && log "built f$VER-$out.ipa" || log "FAILED $out"
}

APPS=${APPS:-template plugins http_demo channel_demo}
want() { [[ " $APPS " == *" $1 "* ]]; }

if want template; then
mkapp template android,ios
apk template template-release --release
apk template template-debug --debug
apk template template-obfuscated --release --obfuscate --split-debug-info="$SRC/symbols/template"
ipa template template-ios-release
fi

if want plugins; then
mkapp plugins android,ios
add_deps plugins "$PLUGINS_PINS" "$PLUGINS_OVERRIDES" shared_preferences flutter_secure_storage webview_flutter
# flutter_secure_storage needs minSdk 18, webview_flutter 19; old templates use 16
[ -n "$PLUGINS_MIN_SDK" ] && sed -i '' "s/minSdkVersion flutter.minSdkVersion/minSdkVersion $PLUGINS_MIN_SDK/" plugins/android/app/build.gradle
cat > plugins/lib/main.dart <<'DART'
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:webview_flutter/webview_flutter.dart';

void main() => runApp(const MaterialApp(home: SettingsPage()));

class SettingsPage extends StatefulWidget {
  const SettingsPage({super.key});
  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  final _storage = const FlutterSecureStorage();
  final _web = WebViewController()..loadRequest(Uri.parse('https://flutter.dev'));
  String _theme = 'light';

  @override
  void initState() {
    super.initState();
    SharedPreferences.getInstance().then((p) => setState(() => _theme = p.getString('theme') ?? 'light'));
    _storage.read(key: 'session');
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: Text('Theme: $_theme')),
        body: WebViewWidget(controller: _web),
      );
}
DART
if [ "$WEBVIEW_API" = 3 ]; then  # webview_flutter 3.x has the WebView widget
  sed -i '' -e '/final _web = WebViewController/d' \
    -e 's/body: WebViewWidget(controller: _web),/body: const WebView(initialUrl: '"'"'https:\/\/flutter.dev'"'"'),/' plugins/lib/main.dart
fi
apk plugins plugins-release --release
apk plugins plugins-obfuscated --release --obfuscate --split-debug-info="$SRC/symbols/plugins"
ipa plugins plugins-ios-release
fi

if want http_demo; then
mkapp http_demo android
add_deps http_demo "$HTTP_PIN" "" http
cat > http_demo/lib/main.dart <<'DART'
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

void main() => runApp(const MaterialApp(home: StatusPage()));

class StatusPage extends StatelessWidget {
  const StatusPage({super.key});
  @override
  Widget build(BuildContext context) => Scaffold(
        body: FutureBuilder<http.Response>(
          future: http.get(Uri.parse('https://flutter.dev')),
          builder: (context, snap) => Center(child: Text('Status: ${snap.data?.statusCode ?? '...'}')),
        ),
      );
}
DART
apk http_demo http-release --release
fi

# App-defined platform channel, as in Flutter's "Writing custom
# platform-specific code" docs (battery level)
if want channel_demo; then
mkapp channel_demo android,ios
cat > channel_demo/lib/main.dart <<'DART'
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

void main() => runApp(const MaterialApp(home: BatteryPage()));

class BatteryPage extends StatefulWidget {
  const BatteryPage({super.key});
  @override
  State<BatteryPage> createState() => _BatteryPageState();
}

class _BatteryPageState extends State<BatteryPage> {
  static const platform = MethodChannel('samples.flutter.dev/battery');
  String _level = 'Unknown battery level.';

  Future<void> _getBatteryLevel() async {
    String level;
    try {
      final result = await platform.invokeMethod<int>('getBatteryLevel');
      level = 'Battery level at $result % .';
    } on PlatformException catch (e) {
      level = "Failed to get battery level: '${e.message}'.";
    }
    setState(() => _level = level);
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        body: Center(
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            ElevatedButton(onPressed: _getBatteryLevel, child: const Text('Get Battery Level')),
            Text(_level),
          ]),
        ),
      );
}
DART
cat > channel_demo/android/app/src/main/kotlin/com/example/channel_demo/MainActivity.kt <<'KT'
package com.example.channel_demo

import android.content.Context
import android.os.BatteryManager
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
  private val channel = "samples.flutter.dev/battery"

  override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
    super.configureFlutterEngine(flutterEngine)
    MethodChannel(flutterEngine.dartExecutor.binaryMessenger, channel).setMethodCallHandler { call, result ->
      if (call.method == "getBatteryLevel") {
        val manager = getSystemService(Context.BATTERY_SERVICE) as BatteryManager
        result.success(manager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY))
      } else {
        result.notImplemented()
      }
    }
  }
}
KT
# Register next to the generated plugins; templates differ by version
sed -i '' -E 's/^([[:space:]]*)GeneratedPluginRegistrant\.register\(with: ([^)]+)\)/&\
\1BatteryChannel.register(with: \2)/' channel_demo/ios/Runner/AppDelegate.swift
cat >> channel_demo/ios/Runner/AppDelegate.swift <<'SWIFT'

enum BatteryChannel {
  static func register(with registry: FlutterPluginRegistry) {
    guard let registrar = registry.registrar(forPlugin: "BatteryChannel") else { return }
    let channel = FlutterMethodChannel(
      name: "samples.flutter.dev/battery", binaryMessenger: registrar.messenger())
    channel.setMethodCallHandler { call, result in
      guard call.method == "getBatteryLevel" else {
        result(FlutterMethodNotImplemented)
        return
      }
      UIDevice.current.isBatteryMonitoringEnabled = true
      let level = UIDevice.current.batteryLevel
      if level < 0 {
        result(FlutterError(code: "UNAVAILABLE", message: "Battery level not available", details: nil))
      } else {
        result(Int(level * 100))
      }
    }
  }
}
SWIFT
apk channel_demo channel-release --release
apk channel_demo channel-obfuscated --release --obfuscate --split-debug-info="$SRC/symbols/channel_demo"
ipa channel_demo channel-ios-release
fi
# Build trees are large; keep sources, drop intermediates
rm -rf "$SRC"/*/build "$SRC"/*/.dart_tool "$SRC"/*/ios/Pods "$SRC"/*/android/.gradle
log "done"; ls -la "$C/apps"/f"$VER"-*
