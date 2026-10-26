"""Command to run the Flutter analysis on a file or directory."""
import json
import sys
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from mobsf.StaticAnalyzer.views.flutter.cli import (
    SEVERITY_RANK,
    scan_path,
    worst_severity,
)
from mobsf.StaticAnalyzer.views.flutter.sarif import to_sarif


class Command(BaseCommand):
    help = ('Flutter security analysis of an APK/AAB/IPA or a Flutter '  # noqa: A003
            'project directory, as JSON or SARIF.')
    # System checks import the URL config, which prints the MobSF banner
    # (incl. the REST API key) to stdout and would corrupt the JSON output
    requires_system_checks = []

    def add_arguments(self, parser):
        parser.add_argument('path', help='APK/AAB/IPA/ZIP file or directory')
        parser.add_argument('--format', choices=['json', 'sarif'],
                            default='json')
        parser.add_argument('--output', help='Write to a file')
        parser.add_argument(
            '--fail-on', choices=list(SEVERITY_RANK),
            help='Exit with code 1 if a finding of this severity or '
                 'higher exists')
        parser.add_argument(
            '--osv', action='store_true',
            help='Look up pubspec.lock packages on api.osv.dev (sends '
                 'package names and versions)')

    def handle(self, *args, **opts):
        try:
            result = scan_path(opts['path'], osv=opts['osv'])
        except FileNotFoundError as exp:
            raise CommandError(f'Not found: {exp}') from exp
        if opts['format'] == 'sarif':
            data = to_sarif(result, artifact_uri=Path(opts['path']).name)
        else:
            data = result
        text = json.dumps(data, indent=2)
        if opts['output']:
            Path(opts['output']).write_text(text, encoding='utf-8')
        else:
            self.stdout.write(text)
        worst = worst_severity(result)
        if (opts['fail_on'] and worst
                and SEVERITY_RANK[worst] <= SEVERITY_RANK[opts['fail_on']]):
            sys.exit(1)
