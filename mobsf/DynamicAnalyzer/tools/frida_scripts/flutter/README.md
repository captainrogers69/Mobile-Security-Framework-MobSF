# Flutter Frida scripts

Frida scripts for Flutter apps (Dart AOT, `libflutter.so` / `Flutter.framework`).

## `ssl-bypass-flutter.js` — TLS verification bypass (F22)

Flutter's HTTP stack uses its own BoringSSL inside `libflutter.so` and ignores
the system proxy and user CA store, so a MITM proxy cannot read its HTTPS
traffic. The script neutralises the engine's certificate check
(`bssl::ssl_verify_peer_cert`), which has no exported symbol and moves with
every engine build.

The engine is identified by its GNU build-id (read from the loaded ELF at
runtime) and the function offset is looked up in the `FLUTTER_SSL_OFFSETS`
table embedded in the script. If the build-id is not in the table, the script
falls back to a byte-pattern scan (arm64 and arm).

Regenerate the table for new engine revisions:

```
python scripts/update_flutter_frida_offsets.py --engine <engine-revision> ...
```

Engine revisions are the keys of
`mobsf/StaticAnalyzer/views/flutter/flutter_engines.json`. The build-id is the
same in the shipped (stripped) library and the symbol archive the generator
reads, so the script matches apps built with that engine. Run it on a rooted
device/emulator; pair with a transparent proxy (Flutter ignores the system
proxy) to capture traffic.

## Planned (see `requirements.md`)

- F23: Platform-channel (`MethodChannel`) tracing
- F24: Runtime storage dump

Available for manual analyst use; not wired into MobSF's automatic script list.
