# -*- coding: utf_8 -*-
"""Look up locked pub packages in the OSV vulnerability database.

Sends package names and versions (hosted packages only) to api.osv.dev;
callers decide whether that is allowed. Returns None when the lookup
fails, so "no vulnerabilities" and "not checked" are distinguishable.
"""
import json
import logging
import re

import requests

from mobsf.MobSF.utils import upstream_proxy

logger = logging.getLogger(__name__)

OSV_BATCH = 'https://api.osv.dev/v1/querybatch'
OSV_VULN = 'https://api.osv.dev/v1/vulns/{}'
OSV_PAGE = 'https://osv.dev/vulnerability/{}'
ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.\-_]{0,63}$')
CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$')
CWE_RE = re.compile(r'^CWE-\d{1,5}$')
SEVERITY = {'CRITICAL': 'critical', 'HIGH': 'high', 'MODERATE': 'medium',
            'MEDIUM': 'medium', 'LOW': 'low'}
BATCH_SIZE = 1000
MAX_VULNS = 200
MAX_RESPONSE = 10 * 1024 * 1024
TIMEOUT = 10


def _read_json(response):
    """Read a JSON response body with a size cap."""
    try:
        if response.status_code != 200:
            return None
        body = b''
        for chunk in response.iter_content(64 * 1024):
            body += chunk
            if len(body) > MAX_RESPONSE:
                return None
        return json.loads(body)
    except (ValueError, requests.RequestException):
        return None
    finally:
        response.close()


def _request_kwargs():
    proxies, verify = upstream_proxy('https')
    return {'timeout': TIMEOUT, 'allow_redirects': False, 'stream': True,
            'proxies': proxies, 'verify': verify}


def _vuln_details(vuln, name):
    fixed = set()
    for affected in vuln.get('affected') or []:
        pkg = affected.get('package') or {}
        if pkg.get('ecosystem') != 'Pub' or pkg.get('name') != name:
            continue
        for rng in affected.get('ranges') or []:
            for event in rng.get('events') or []:
                if isinstance(event.get('fixed'), str):
                    fixed.add(event['fixed'][:64])
    db = vuln.get('database_specific') or {}
    return {
        'id': vuln['id'],
        'summary': str(vuln.get('summary') or '')[:300],
        'aliases': sorted(a for a in vuln.get('aliases') or []
                          if isinstance(a, str) and CVE_RE.match(a)),
        'severity': SEVERITY.get(str(db.get('severity', '')).upper(),
                                 'unknown'),
        'cwe': sorted(c for c in db.get('cwe_ids') or []
                      if isinstance(c, str) and CWE_RE.match(c)),
        'fixed': sorted(fixed),
        'url': OSV_PAGE.format(vuln['id']),
    }


def osv_vulnerabilities(packages, session=None):
    """Return [{'name', 'version', 'dependency', 'vulns'}] or None."""
    http = session or requests
    hosted = [p for p in packages if p.get('source') == 'hosted']
    if not hosted:
        return []
    kwargs = {} if session else _request_kwargs()
    ids_by_pkg = []
    try:
        for start in range(0, len(hosted), BATCH_SIZE):
            batch = hosted[start:start + BATCH_SIZE]
            queries = [{'package': {'name': p['name'], 'ecosystem': 'Pub'},
                        'version': p['version']} for p in batch]
            data = _read_json(
                http.post(OSV_BATCH, json={'queries': queries}, **kwargs))
            results = data.get('results') if isinstance(data, dict) else None
            if not isinstance(results, list) or len(results) != len(batch):
                return None
            for pkg, result in zip(batch, results):
                vulns = result.get('vulns') if isinstance(result, dict) else []
                ids = [v.get('id') for v in vulns or []
                       if isinstance(v, dict)]
                ids_by_pkg.append(
                    (pkg, [i for i in ids if isinstance(i, str)
                           and ID_RE.match(i)]))
        details = {}
        for vid in sorted({i for _, ids in ids_by_pkg for i in ids}):
            if len(details) >= MAX_VULNS:
                break
            vuln = _read_json(http.get(OSV_VULN.format(vid), **kwargs))
            if isinstance(vuln, dict) and vuln.get('id') == vid:
                details[vid] = vuln
    except requests.RequestException:
        logger.warning('OSV lookup failed')
        return None
    result = []
    for pkg, ids in ids_by_pkg:
        vulns = [_vuln_details(details[i], pkg['name'])
                 for i in ids if i in details]
        if vulns:
            result.append({'name': pkg['name'], 'version': pkg['version'],
                           'dependency': pkg.get('dependency', ''),
                           'vulns': vulns})
    return result
