# MobSF environment variables

All variables MobSF reads from the process environment, from
`mobsf/MobSF/settings.py`, `mobsf/MobSF/env.py`, `mobsf/MobSF/init.py` and
`mobsf/MobSF/tools_download.py`. Template: [`.env.example`](../.env.example).

## Read this first: how flags are parsed

Every flag uses one rule (`mobsf/MobSF/env.py`, since MobSF#2724): **only the value
`1` turns it on** (`"1"` with quotes also works). `0`, empty, unset, `true`, `yes`
and anything else mean **off**.

Where a flag can also be set in `~/.MobSF/config.py`:

- A set environment variable wins, including `0`.
- Otherwise the `config.py` value is used with the same rule; a Python `True`
  written there by hand still counts as on.

`config.py` is generated once, on first run, and is not updated afterwards. Settings
that only live there (e.g. `SKIP_CLASS_PATH`) keep their old values after upgrades.

## Core

| Variable | Default | On when | Purpose |
|---|---|---|---|
| `MOBSF_SECRET_KEY` | auto-generated in `~/.MobSF/secret` | | Django `SECRET_KEY` |
| `MOBSF_API_KEY` | auto-generated | | REST API key |
| `MOBSF_API_KEY_FILE` | | | Path to a Docker secret holding the API key; takes precedence over `MOBSF_API_KEY` |
| `MOBSF_DEBUG` | `0` | `1` | Django debug mode. Never in production |
| `MOBSF_DISABLE_AUTHENTICATION` | unset | `1` | Turns off login. Local testing only |
| `MOBSF_API_ONLY` | `0` | `1` | REST API only, no web UI routes |
| `MOBSF_HOME_DIR` | `~/.MobSF` | | Custom data directory; must be an existing absolute directory |
| `MOBSF_RATELIMIT` | `7/m` | | Login rate limit |
| `MOBSF_USE_X_FORWARDED_HOST` | `1` | `1` | Trust `X-Forwarded-Host` (behind a reverse proxy) |
| `MOBSF_USE_X_FORWARDED_PORT` | `1` | `1` | Trust `X-Forwarded-Port` |
| `TIME_ZONE` | `UTC` | | Django time zone |

## Database (PostgreSQL; SQLite when unset)

PostgreSQL is used only when `POSTGRES_USER`, `POSTGRES_HOST` and either
`POSTGRES_PASSWORD` or `POSTGRES_PASSWORD_FILE` are all set.

| Variable | Default | Purpose |
|---|---|---|
| `POSTGRES_USER` | | Username |
| `POSTGRES_PASSWORD` | | Password |
| `POSTGRES_PASSWORD_FILE` | | Docker secret file with the password |
| `POSTGRES_HOST` | | Host |
| `POSTGRES_PORT` | `5432` | Port |
| `POSTGRES_DB` | `mobsf` | Database name |

## Analysis queue and timeouts

| Variable | Default | On when | Purpose |
|---|---|---|---|
| `MOBSF_ASYNC_ANALYSIS` | `0` | `1` | Queue scans in the background |
| `MOBSF_ASYNC_ANALYSIS_TIMEOUT` | `60` | | Async task timeout (minutes) |
| `MOBSF_ASYNC_WORKERS` | `2` | | Async worker count |
| `MOBSF_MULTIPROCESSING` | auto | | SAST strategy override: `default`, `billiard` or `thread` |
| `MOBSF_JADX_TIMEOUT` | `1000` | | jadx decompile timeout (s) |
| `MOBSF_SAST_TIMEOUT` | `1000` | | SAST timeout (s) |
| `MOBSF_BINARY_ANALYSIS_TIMEOUT` | `600` | | Binary analysis timeout (s) |

## Static analysis features

| Variable | Default | On when | Purpose |
|---|---|---|---|
| `MOBSF_APKID_ENABLED` | `1` | `1` | APKiD packer/obfuscator detection |
| `MOBSF_DEX2SMALI_ENABLED` | `1` | `1` | DEX to smali conversion |
| `MOBSF_SO_ANALYSIS_ENABLED` | `1` | `1` | Android `.so` analysis |
| `MOBSF_DYLIB_ANALYSIS_ENABLED` | `1` | `1` | iOS dylib analysis |
| `MOBSF_PERM_MAPPING_ENABLED` | `1` | `1` | Permission-to-API mapping |
| `MOBSF_DOMAIN_MALWARE_SCAN` | `1` | `1` | Malware domain check (outbound requests) |
| `MOBSF_NIAP_ENABLED` | `0` | `1` | NIAP checks |
| `MOBSF_CVSS_SCORE_ENABLED` | `0` | `1` | CVSS v2 scores in reports |
| `EFR_01` | `0` | `1` | Report some findings as `hotspot` instead of high/warning |

## Flutter analysis (this fork)

See [`docs/flutter.md`](flutter.md).

| Variable | Default | On when | Purpose |
|---|---|---|---|
| `MOBSF_FLUTTER_OSV_ENABLED` | `0` | `1` | Look up `pubspec.lock` packages of Flutter project ZIPs on api.osv.dev. **Sends dependency names and versions to a third party.** |

## External tool overrides

Optional absolute paths. When empty, MobSF uses the bundled or downloaded tool.

`MOBSF_JADX_BINARY`, `MOBSF_BACKSMALI_BINARY`, `MOBSF_VD2SVG_BINARY`,
`MOBSF_APKTOOL_BINARY`, `MOBSF_ADB_BINARY`, `MOBSF_AAPT_BINARY`,
`MOBSF_AAPT2_BINARY`, `MOBSF_BUNDLE_TOOL`, `MOBSF_JTOOL_BINARY`,
`MOBSF_CLASSDUMP_BINARY`, `MOBSF_CLASSDUMP_SWIFT_BINARY`,
`MOBSF_JAVA_DIRECTORY` (falls back to `JAVA_HOME`).

## Third-party services

| Variable | Default | On when | Purpose |
|---|---|---|---|
| `MOBSF_VT_ENABLED` | `0` | `1` | VirusTotal hash lookup |
| `MOBSF_VT_API_KEY` | | | VirusTotal API key (secret) |
| `MOBSF_VT_UPLOAD` | `0` | `1` | **Uploads app binaries to VirusTotal.** Keep `0` for confidential apps |
| `MOBSF_APPMONSTA_API` | | | AppMonsta API key for store lookups |

## Upstream (outbound) proxy

| Variable | Default | On when | Purpose |
|---|---|---|---|
| `MOBSF_UPSTREAM_PROXY_ENABLED` | `0` | `1` | Route MobSF's outbound requests through a proxy |
| `MOBSF_UPSTREAM_PROXY_TYPE` | `http` | | Proxy URL scheme |
| `MOBSF_UPSTREAM_PROXY_IP` | `127.0.0.1` | | Proxy host |
| `MOBSF_UPSTREAM_PROXY_PORT` | `3128` | | Proxy port |
| `MOBSF_UPSTREAM_PROXY_USERNAME` | | | Proxy user |
| `MOBSF_UPSTREAM_PROXY_PASSWORD` | | | Proxy password (secret) |
| `MOBSF_UPSTREAM_PROXY_SSL_VERIFY` | `1` | `1` | Verify TLS through the proxy |

## Dynamic analysis

| Variable | Default | Purpose |
|---|---|---|
| `MOBSF_ANALYZER_IDENTIFIER` | | Android device/emulator `ip:port` or serial (`ANALYZER_IDENTIFIER` also accepted) |
| `MOBSF_PROXY_IP` | `127.0.0.1` | Interception proxy IP as seen by the device |
| `MOBSF_PROXY_PORT` | `1337` | Interception proxy port |
| `MOBSF_FRIDA_TIMEOUT` | `4` | Frida attach wait (s) |
| `MOBSF_ACTIVITY_TESTER_SLEEP` | `4` | Delay between activity launches (s) |
| `MOBSF_IOS_ANALYZER_IDENTIFIERS` | | iOS device identifiers |
| `MOBSF_IOS_SSH_USER` | `root` | Jailbroken iOS SSH user |
| `MOBSF_IOS_SSH_PASSWORD` | `alpine` | Jailbroken iOS SSH password. Change it on the device |
| `MOBSF_CORELLIUM_API_DOMAIN` | | Corellium API domain |
| `MOBSF_CORELLIUM_API_KEY` | | Corellium API key (secret) |
| `MOBSF_CORELLIUM_PROJECT_ID` | | Corellium project |
| `MOBSF_WINDOWS_VM_IP` | | Windows analysis VM IP |
| `MOBSF_WINDOWS_VM_PORT` | `8000` | Windows analysis VM port |

## SAML SSO

| Variable | Default | Purpose |
|---|---|---|
| `MOBSF_IDP_METADATA_URL` | | IdP metadata URL (or set the three below) |
| `MOBSF_IDP_ENTITY_ID` | | IdP entity ID |
| `MOBSF_IDP_SSO_URL` | | IdP SSO URL |
| `MOBSF_IDP_X509CERT` | | IdP signing certificate |
| `MOBSF_IDP_IS_ADFS` | `0` | Set to `1` for ADFS |
| `MOBSF_IDP_MAINTAINER_GROUP` | `Maintainer` | IdP group mapped to Maintainer |
| `MOBSF_IDP_VIEWER_GROUP` | `Viewer` | IdP group mapped to Viewer |
| `MOBSF_SP_HOST` | | Public MobSF URL for SAML callbacks |
| `MOBSF_SP_ALLOW_PASSWORD` | `0` | Set to `1` to keep password login alongside SSO |

## Internal (do not set)

`MOBSF_PLATFORM` (set to `docker` by the image), `MOBSF_ADB` (set at runtime).
