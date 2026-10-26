# -*- coding: utf_8 -*-
"""Convert a Flutter analysis result to SARIF 2.1.0.

Secret values are redacted: SARIF files are often uploaded to code
scanning services, which must not receive the secrets themselves.
"""
import re

SARIF_SCHEMA = ('https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/'
                'os/schemas/sarif-schema-2.1.0.json')
INFO_URI = 'https://github.com/MobSF/Mobile-Security-Framework-MobSF'
LEVELS = {'high': 'error', 'warning': 'warning', 'info': 'note'}
# GitHub code scanning ranks results by security-severity (0-10)
SCORES = {'high': '8.0', 'warning': '5.0', 'info': '2.0'}
KEY_VALUE_RE = re.compile(r'^(".{1,200}?" : ")(.*)(")$', re.DOTALL)
LABEL_RE = re.compile(r'^([A-Za-z0-9 ._()-]{1,80}): (.+)$', re.DOTALL)
CWE_RE = re.compile(r'cwe-(\d{1,5})', re.IGNORECASE)
MASVS_RE = re.compile(r'(?:MSTG-|MASVS-)?([A-Za-z]+-\d+)$')
SECRET_RULE = 'flutter_asset_secret'


def _mask(value):
    return f'{value[:4]}****' if len(value) >= 8 else '****'


def redact_secret(secret):
    """Keep the key or label of a secret, mask most of its value."""
    match = KEY_VALUE_RE.match(secret)
    if match:
        return f'{match.group(1)}{_mask(match.group(2))}{match.group(3)}'
    match = LABEL_RE.match(secret)
    if match:
        return f'{match.group(1)}: {_mask(match.group(2))}'
    return '****'


def _tags(cwe, masvs):
    tags = ['security']
    match = CWE_RE.search(cwe or '')
    if match:
        tags.append(f'CWE-{match.group(1)}')
    match = MASVS_RE.search((masvs or '').strip())
    if match:
        tags.append(f'MASVS-{match.group(1).upper()}')
    return tags


def _location(uri, line=1):
    return {'physicalLocation': {
        'artifactLocation': {'uri': uri},
        'region': {'startLine': line},
    }}


def _lines(value):
    lines = []
    for part in str(value).split(','):
        part = part.strip()
        if part.isdigit() and int(part) > 0:
            lines.append(int(part))
    return lines or [1]


def to_sarif(result, artifact_uri='app'):
    """Return a SARIF 2.1.0 document for a Flutter analysis result."""
    rules, results = {}, []
    root = result.get('project_root') or ''
    prefix = '' if root in ('', '.') else root.rstrip('/') + '/'

    def add_rule(rule_id, title, description, severity, cwe, masvs):
        rules.setdefault(rule_id, {
            'id': rule_id,
            'name': rule_id,
            'shortDescription': {'text': title[:200]},
            'fullDescription': {'text': description[:1000]},
            'defaultConfiguration': {'level': LEVELS[severity]},
            'properties': {'tags': _tags(cwe, masvs),
                           'security-severity': SCORES[severity]},
        })

    for finding in result.get('findings') or []:
        severity = finding.get('severity')
        if severity not in LEVELS:
            continue
        add_rule(finding['id'], finding['title'], finding['description'],
                 severity, finding.get('cwe'), finding.get('masvs'))
        packages = finding.get('packages') or []
        text = f'{finding["title"]}: {finding["description"]}'
        if packages:
            text += f' Packages: {", ".join(packages)}.'
        results.append({'ruleId': finding['id'], 'level': LEVELS[severity],
                        'message': {'text': text},
                        'locations': [_location(artifact_uri)]})
    for rule_id, details in (result.get('code_analysis') or {}).items():
        meta = details.get('metadata') or {}
        severity = meta.get('severity')
        if severity not in LEVELS:
            continue
        desc = str(meta.get('description', rule_id))
        add_rule(rule_id, desc, desc, severity, meta.get('cwe'),
                 meta.get('masvs'))
        for path, lines in (details.get('files') or {}).items():
            results.append({
                'ruleId': rule_id, 'level': LEVELS[severity],
                'message': {'text': desc},
                'locations': [_location(prefix + path, line)
                              for line in _lines(lines)]})
    for entry in result.get('asset_secrets') or []:
        add_rule(SECRET_RULE, 'Secret in bundled asset',
                 'A bundled asset file contains a secret. Values are '
                 'redacted in this report.', 'warning', 'cwe-798',
                 'storage-14')
        redacted = ', '.join(redact_secret(s) for s in entry['secrets'])
        results.append({
            'ruleId': SECRET_RULE, 'level': 'warning',
            'message': {'text': f'Secrets found: {redacted}'},
            'locations': [_location(prefix + entry['file'])]})
    return {
        '$schema': SARIF_SCHEMA,
        'version': '2.1.0',
        'runs': [{
            'tool': {'driver': {'name': 'MobSF Flutter',
                                'informationUri': INFO_URI,
                                'rules': list(rules.values())}},
            'results': results,
        }],
    }
