"""Command to compare the Flutter analysis of two app versions."""
import json
import sys
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from mobsf.StaticAnalyzer.views.flutter.cli import SEVERITY_RANK
from mobsf.StaticAnalyzer.views.flutter.diff import (
    diff_results,
    diff_text,
    load_diff_input,
    new_risk,
)


class Command(BaseCommand):
    help = ('Compare the Flutter analysis of two app versions: new, '  # noqa: A003
            'fixed and changed findings, packages and versions.')
    # System checks import the URL config, which prints the MobSF banner
    # (incl. the REST API key) to stdout and would corrupt the JSON output
    requires_system_checks = []

    def add_arguments(self, parser):
        for name in ('old', 'new'):
            parser.add_argument(
                name, help=f'{name.title()} version: APK/AAB/IPA/ZIP file, '
                'directory, flutter_scan JSON or MobSF report JSON')
        parser.add_argument('--format', choices=['text', 'json'],
                            default='text')
        parser.add_argument('--output', help='Write to a file')
        parser.add_argument(
            '--fail-on-new', choices=list(SEVERITY_RANK),
            help='Exit with code 1 if the new version adds a finding of '
                 'this severity or higher')
        parser.add_argument(
            '--osv', action='store_true',
            help='Look up pubspec.lock packages on api.osv.dev when scanning '
                 '(sends package names and versions)')

    def handle(self, *args, **opts):
        try:
            old = load_diff_input(opts['old'], osv=opts['osv'])
            new = load_diff_input(opts['new'], osv=opts['osv'])
        except FileNotFoundError as exp:
            raise CommandError(f'Not found: {exp}') from exp
        except ValueError as exp:
            raise CommandError(str(exp)) from exp
        diff = diff_results(old, new)
        if opts['format'] == 'json':
            text = json.dumps(diff, indent=2)
        else:
            text = diff_text(diff)
        if opts['output']:
            Path(opts['output']).write_text(text, encoding='utf-8')
        else:
            self.stdout.write(text)
        worst = new_risk(diff)
        if (opts['fail_on_new'] and worst
                and SEVERITY_RANK[worst] <= SEVERITY_RANK[opts['fail_on_new']]):
            sys.exit(1)
