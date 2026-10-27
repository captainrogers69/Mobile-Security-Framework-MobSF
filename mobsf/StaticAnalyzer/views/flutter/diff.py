# -*- coding: utf_8 -*-
"""Compare the Flutter analysis of two versions of an app.

Findings and Dart rules are matched by id, packages by name. Line
numbers are ignored (they move between versions), so a Dart rule only
counts as changed when it hits a new file. Secret values are masked.
"""
import json
from pathlib import Path

from mobsf.StaticAnalyzer.views.flutter.cli import SEVERITY_RANK, scan_path
from mobsf.StaticAnalyzer.views.flutter.fileio import open_regular
from mobsf.StaticAnalyzer.views.flutter.sarif import redact_secret

MAX_JSON_SIZE = 64 * 1024 * 1024
FACTS = ('platform', 'build_mode', 'flutter', 'dart', 'obfuscated')
# Asset secrets have no severity of their own; SARIF reports them as warning
SECRET_SEVERITY = 'warning'


def load_diff_input(path, osv=False):
    """Flutter result from flutter_scan JSON, MobSF report JSON or an app."""
    path = Path(path)
    if path.suffix.lower() != '.json':
        return scan_path(path, osv=osv)
    fobj = open_regular(path, MAX_JSON_SIZE)
    if fobj is None:
        raise ValueError(f'Not a regular file or too large: {path}')
    with fobj:
        data = json.loads(fobj.read().decode('utf-8'))
    # MobSF report JSON keeps the Flutter result under 'flutter'
    if (isinstance(data, dict) and 'is_flutter' not in data
            and isinstance(data.get('flutter'), dict)):
        data = data['flutter']
    if not isinstance(data, dict) or not data.get('is_flutter'):
        raise ValueError(f'No Flutter analysis result in {path}')
    return data


def _findings(result):
    return {f['id']: f for f in result.get('findings') or []
            if isinstance(f, dict) and 'id' in f}


def _rules(result):
    rules = {}
    for rule_id, details in (result.get('code_analysis') or {}).items():
        meta = details.get('metadata') or {}
        rules[rule_id] = (meta.get('severity'),
                          set(details.get('files') or {}))
    return rules


def _packages(result):
    packages = {}
    for pkg in result.get('packages') or []:
        if isinstance(pkg, dict) and pkg.get('name'):
            packages[pkg['name']] = pkg.get('version') or ''
        elif isinstance(pkg, str):
            packages[pkg] = ''
    return packages


def _secrets(result):
    return {(entry['file'], secret)
            for entry in result.get('asset_secrets') or []
            for secret in entry.get('secrets') or []}


def _rule_entry(rule_id, severity, files):
    return {'id': rule_id, 'severity': severity, 'files': sorted(files)}


def diff_results(old, new):
    """Differences between two Flutter analysis results."""
    old_f, new_f = _findings(old), _findings(new)
    both = sorted(set(old_f) & set(new_f))
    changed = [{'id': i, 'title': new_f[i].get('title', i),
                'old_severity': old_f[i].get('severity'),
                'new_severity': new_f[i].get('severity')}
               for i in both
               if old_f[i].get('severity') != new_f[i].get('severity')]
    old_r, new_r = _rules(old), _rules(new)
    new_files = []
    for rule_id in sorted(set(old_r) & set(new_r)):
        added = new_r[rule_id][1] - old_r[rule_id][1]
        if added:
            new_files.append(_rule_entry(rule_id, new_r[rule_id][0], added))
    old_p, new_p = _packages(old), _packages(new)
    old_s, new_s = _secrets(old), _secrets(new)
    return {
        'facts': {k: {'old': old.get(k), 'new': new.get(k)}
                  for k in FACTS if old.get(k) != new.get(k)},
        'findings': {
            'new': [new_f[i] for i in sorted(set(new_f) - set(old_f))],
            'fixed': [old_f[i] for i in sorted(set(old_f) - set(new_f))],
            'changed': changed,
            'unchanged': len(both) - len(changed),
        },
        'code_analysis': {
            'new': [_rule_entry(i, *new_r[i])
                    for i in sorted(set(new_r) - set(old_r))],
            'fixed': [_rule_entry(i, *old_r[i])
                      for i in sorted(set(old_r) - set(new_r))],
            'new_files': new_files,
        },
        'packages': {
            'added': [{'name': n, 'version': new_p[n]}
                      for n in sorted(set(new_p) - set(old_p))],
            'removed': [{'name': n, 'version': old_p[n]}
                        for n in sorted(set(old_p) - set(new_p))],
            'changed': [{'name': n, 'old': old_p[n], 'new': new_p[n]}
                        for n in sorted(set(old_p) & set(new_p))
                        if old_p[n] != new_p[n]],
        },
        'secrets': {
            'new': [{'file': f, 'secret': redact_secret(s)}
                    for f, s in sorted(new_s - old_s)],
            'removed': len(old_s - new_s),
        },
    }


def new_risk(diff):
    """Worst severity the new version adds, or None."""
    severities = [f.get('severity') for f in diff['findings']['new']]
    severities += [
        c['new_severity'] for c in diff['findings']['changed']
        if SEVERITY_RANK.get(c['new_severity'], 99)
        < SEVERITY_RANK.get(c['old_severity'], 99)]
    severities += [r['severity'] for r in diff['code_analysis']['new']]
    severities += [r['severity'] for r in diff['code_analysis']['new_files']]
    if diff['secrets']['new']:
        severities.append(SECRET_SEVERITY)
    ranked = [s for s in severities if s in SEVERITY_RANK]
    return min(ranked, key=SEVERITY_RANK.get) if ranked else None


def _versions(value):
    if isinstance(value, list):
        return ', '.join(str(v) for v in value) or '-'
    return '-' if value is None else str(value)


def diff_text(diff):
    """Human-readable summary of a diff."""
    lines = []
    for key, change in diff['facts'].items():
        lines.append(f'{key}: {_versions(change["old"])} -> '
                     f'{_versions(change["new"])}')
    findings = diff['findings']
    sections = (
        ('New findings', [f'[{f.get("severity")}] {f["id"]}: '
                          f'{f.get("title", "")}' for f in findings['new']]),
        ('Fixed findings', [f'[{f.get("severity")}] {f["id"]}: '
                            f'{f.get("title", "")}'
                            for f in findings['fixed']]),
        ('Severity changed', [f'{c["id"]}: {c["old_severity"]} -> '
                              f'{c["new_severity"]}'
                              for c in findings['changed']]),
        ('New Dart rule hits', [
            f'[{r["severity"]}] {r["id"]}: {", ".join(r["files"])}'
            for r in (diff['code_analysis']['new']
                      + diff['code_analysis']['new_files'])]),
        ('Fixed Dart rules', [f'[{r["severity"]}] {r["id"]}'
                              for r in diff['code_analysis']['fixed']]),
        ('Packages added', [f'{p["name"]} {p["version"]}'.strip()
                            for p in diff['packages']['added']]),
        ('Packages removed', [f'{p["name"]} {p["version"]}'.strip()
                              for p in diff['packages']['removed']]),
        ('Packages changed', [f'{p["name"]}: {p["old"]} -> {p["new"]}'
                              for p in diff['packages']['changed']]),
        ('New secrets in assets', [f'{s["file"]}: {s["secret"]}'
                                   for s in diff['secrets']['new']]),
    )
    for title, items in sections:
        if items:
            lines.append(f'\n{title} ({len(items)}):')
            lines.extend(f'  {item}' for item in items)
    lines.append(f'\nUnchanged findings: {findings["unchanged"]}; '
                 f'secrets removed: {diff["secrets"]["removed"]}')
    return '\n'.join(lines).strip() + '\n'
