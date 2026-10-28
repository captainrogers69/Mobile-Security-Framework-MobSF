#!/usr/bin/env python3
# -*- coding: utf_8 -*-
"""Transparent MITM helper for Flutter apps on a rooted Android device/emulator.

Flutter ships its own BoringSSL in `libflutter.so` and ignores the system HTTP
proxy and user CA store, so its HTTPS traffic is invisible to a normal proxy.
Two things are needed to read it: the TLS-verification bypass
(`frida_scripts/flutter/ssl-bypass-flutter.js`, which makes the app accept the
proxy's certificate) and transparent routing of the app's traffic into the
proxy (this script).

The commands are deliberate and separate so an analyst can see each step:

    # 1. start mitmproxy on the host (single-host target shown; see --help notes)
    mitmdump --mode reverse:https://api.example.com:443 -p 8080

    # 2. route the device's 443/80 into it
    python scripts/flutter_mitm.py wire

    # 3. run the app with the TLS bypass and watch decrypted traffic in mitmproxy
    python scripts/flutter_mitm.py hook com.example.app

    # 4. restore the device
    python scripts/flutter_mitm.py unwire

Transport notes:
- The device reaches the host proxy over `adb reverse` (device 127.0.0.1:<port>
  -> host proxy), which avoids emulator NIC/routing quirks. `route_localnet` is
  enabled so the DNAT to 127.0.0.1 is allowed.
- `mitmdump --mode transparent` cannot recover the original destination from a
  device-side DNAT on macOS, so use reverse mode for a single host, or
  `mitmdump --mode wireguard` (with a WireGuard client on the device) for
  arbitrary hosts. On a Linux host, classic transparent mode + TPROXY also works.
- The Frida bypass makes the app accept the proxy's certificate, so no CA needs
  to be installed on the device.

This is a manual analyst tool. It is not imported by MobSF's scan or dynamic
analyzer and does not change their behaviour.
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path

SSL_BYPASS = (Path(__file__).resolve().parent.parent / 'mobsf'
              / 'DynamicAnalyzer' / 'tools' / 'frida_scripts' / 'flutter'
              / 'ssl-bypass-flutter.js')
PORTS = ('443', '80')


def find_adb():
    """Locate the adb binary from the environment or the default SDK path."""
    env = os.environ.get('ADB')
    if env and Path(env).exists():
        return env
    for base in (os.environ.get('ANDROID_SDK_ROOT'),
                 os.environ.get('ANDROID_HOME'),
                 str(Path.home() / 'Library' / 'Android' / 'sdk'),
                 str(Path.home() / 'Android' / 'Sdk')):
        if base:
            cand = Path(base) / 'platform-tools' / 'adb'
            if cand.exists():
                return str(cand)
    return 'adb'


def adb_args(args):
    base = [args.adb]
    if args.serial:
        base += ['-s', args.serial]
    return base


def adb(args, *cmd, check=True, capture=False):
    full = adb_args(args) + list(cmd)
    return subprocess.run(full, check=check, text=True,
                          capture_output=capture)


def su(args, shell_cmd, check=True):
    """Run a command as root on the device via `su 0`."""
    return adb(args, 'shell', f'su 0 {shell_cmd}', check=check, capture=True)


def wire(args):
    adb(args, 'reverse', f'tcp:{args.port}', f'tcp:{args.port}')
    su(args, 'sysctl -w net.ipv4.conf.all.route_localnet=1')
    for port in PORTS:
        su(args, f'iptables -t nat -A OUTPUT -p tcp --dport {port} '
           f'-j DNAT --to-destination 127.0.0.1:{args.port}')
    print(f'wired: device tcp 443/80 -> 127.0.0.1:{args.port} '
          f'-> (adb reverse) host :{args.port}')
    print('start the proxy on the host, e.g.:')
    print(f'  mitmdump --mode reverse:https://TARGET_HOST:443 -p {args.port}')


def unwire(args):
    su(args, 'iptables -t nat -F OUTPUT', check=False)
    su(args, 'sysctl -w net.ipv4.conf.all.route_localnet=0', check=False)
    adb(args, 'reverse', '--remove', f'tcp:{args.port}', check=False)
    print('unwired: DNAT flushed, route_localnet reset, adb reverse removed')


def hook(args):
    try:
        import frida
    except ImportError:
        sys.exit('frida is required for "hook": pip install frida-tools')
    script_path = Path(args.script)
    if not script_path.exists():
        sys.exit(f'script not found: {script_path}')
    src = script_path.read_text(encoding='utf-8')
    dev = frida.get_usb_device(timeout=10)

    def on_message(message, _data):
        if message['type'] == 'send':
            print('  [send]', message.get('payload'))
        else:
            print('  [err]', message.get('description', message))

    pid = dev.spawn([args.package])
    session = dev.attach(pid)
    script = session.create_script(src)
    script.on('message', on_message)
    script.set_log_handler(lambda level, text: print(f'  [{level}] {text}'))
    script.load()
    dev.resume(pid)
    print(f'hooked {args.package} (pid {pid}); Ctrl-C to stop')
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            dev.kill(pid)
        except frida.ProcessNotFoundError:
            pass


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--adb', default=find_adb(), help='path to adb')
    parser.add_argument('--serial', help='adb device serial (-s)')
    parser.add_argument('--port', default='8080',
                        help='host proxy port (default 8080)')
    sub = parser.add_subparsers(dest='cmd', required=True)
    sub.add_parser('wire', help='route device 443/80 into the host proxy')
    sub.add_parser('unwire', help='remove the routing and restore the device')
    h = sub.add_parser('hook', help='spawn an app with the TLS bypass')
    h.add_argument('package', help='app package name')
    h.add_argument('--script', default=str(SSL_BYPASS),
                   help='Frida script (default: the shipped TLS bypass)')
    args = parser.parse_args(argv)
    {'wire': wire, 'unwire': unwire, 'hook': hook}[args.cmd](args)


if __name__ == '__main__':
    main()
