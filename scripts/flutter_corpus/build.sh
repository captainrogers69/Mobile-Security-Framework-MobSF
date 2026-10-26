#!/bin/bash
# Build a small corpus of ordinary Flutter apps.
set -u
C=$(cd "$(dirname "$0")" && pwd)
cd "$C/src"
log() { echo "[$(date +%H:%M:%S)] $*"; }

mkapp() {  # name platforms
  rm -rf "$1" && flutter create --platforms="$2" --org com.example "$1" > "$1.create.log" 2>&1
  [ -f "$1/ios/Runner.xcodeproj/project.pbxproj" ] && sed -i '' 's/IPHONEOS_DEPLOYMENT_TARGET = 13.0;/IPHONEOS_DEPLOYMENT_TARGET = 15.0;/g' "$1/ios/Runner.xcodeproj/project.pbxproj"
}
apk() {  # app out-name extra-args...
  local app=$1 out=$2; shift 2
  (cd "$C/src/$app" && flutter build apk "$@" > "$C/apps/$out.build.log" 2>&1) && \
    cp "$C/src/$app/build/app/outputs/flutter-apk/app-$( [[ " $* " == *" --debug "* ]] && echo debug || echo release ).apk" "$C/apps/$out.apk" && log "built $out.apk" || log "FAILED $out"
}
ipa() {  # app out-name extra-args...
  local app=$1 out=$2; shift 2
  (cd "$C/src/$app" && flutter build ios --release --no-codesign "$@" > "$C/apps/$out.build.log" 2>&1) && \
    rm -rf "$C/src/_ipa" && mkdir -p "$C/src/_ipa/Payload" && cp -R "$C/src/$app/build/ios/iphoneos/Runner.app" "$C/src/_ipa/Payload/" && \
    (cd "$C/src/_ipa" && rm -f "$C/apps/$out.ipa" && zip -qr "$C/apps/$out.ipa" Payload) && log "built $out.ipa" || log "FAILED $out"
}

mkapp template android,ios
apk template template-release --release
apk template template-debug --debug
apk template template-obfuscated --release --obfuscate --split-debug-info="$C/src/symbols/template"
ipa template template-ios-release

mkapp plugins android,ios
(cd plugins && flutter pub add shared_preferences flutter_secure_storage webview_flutter > ../plugins.pub.log 2>&1)
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
apk plugins plugins-release --release
apk plugins plugins-obfuscated --release --obfuscate --split-debug-info="$C/src/symbols/plugins"
ipa plugins plugins-ios-release

mkapp http_demo android
(cd http_demo && flutter pub add http > ../http_demo.pub.log 2>&1)
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
log "done"; ls -la "$C/apps"/*.apk "$C/apps"/*.ipa
