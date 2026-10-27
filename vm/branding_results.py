#!/usr/bin/env python3
"""Check scoped branding against an unbranded guest and retained native milestones."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build'))
from install_branding_overlay import STAGES, verify_pair

CASES = ('nt51_x86_build_identity', 'ansi_unicode_version_agree', 'rtl_version_identity',
         'product_name_legacy_detection', 'verify_version_info_legacy', 'protected_identity_snapshot',
         'winver_scoped_resource', 'branding_label_metrics_96_120_144dpi', 'legacy_setup_directory',
         'legacy_setup_file_copy', 'legacy_setup_registration', 'legacy_installed_application_version_detection',
         'legacy_setup_file_uninstall', 'legacy_setup_registry_uninstall',
         'legacy_calculator_arithmetic', 'branding_probe_complete')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def latest_probe(text):
    # A later incomplete probe must not inherit an earlier passing result.
    start = text.rfind('BRANDING_PROBE_STARTED')
    end = text.find('BRANDING_PROBE_EXIT=', start) if start >= 0 else -1
    records = []
    for line in text[start:end].splitlines() if start >= 0 and end >= 0 else []:
        try:
            records.append(json.loads(line))
        except ValueError:
            pass
    return end, records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--stage', choices=('baseline', *STAGES), required=True)
    parser.add_argument('--notepad-marker', help='exact text saved through Notepad in this final guest')
    args = parser.parse_args()
    if args.stage == 'login' and not args.notepad_marker:
        parser.error('final branding requires a unique Notepad readback marker')
    directory, baseline, package = (p.resolve() for p in (args.directory, args.baseline, args.package))
    if any(not p.is_relative_to(ROOT / '.work') for p in (directory, baseline, package)):
        parser.error('private .work/ evidence required')
    text = (directory / 'serial.log').read_text(errors='replace')
    end, records = latest_probe(text)
    _, base_records = latest_probe((baseline / 'serial.log').read_text(errors='replace'))
    cases = CASES + (('login_scoped_resource',) if args.stage == 'login' else ())
    rows = {row['branding_case']: row for row in records if row.get('branding_case') in cases}
    identity = [row for row in records if row.get('branding_identity')]
    base_identity = [row for row in base_records if row.get('branding_identity')]
    msi = text[text.rfind('MSI_BUILD_EXIT='):]
    manifest = json.loads((package / 'manifest.json').read_text())
    original = Path(manifest['inputs']).resolve()
    if not original.is_relative_to(ROOT / '.work'):
        parser.error('private original resource inputs required')
    active = []
    for stage in STAGES:
        if args.stage == 'baseline':
            break
        active.extend(STAGES[stage])
        if stage == args.stage:
            break
    retention = directory / 'retention'
    resource_checks = {}
    for name, row in manifest['components'].items():
        retained = retention / 'WINDOWS' / name
        expected = row['sha256'] if name in active else row['original_sha256']
        ok = retained.is_file() and sha(retained) == expected and sha(original / name) == row['original_sha256']
        if ok:
            verify_pair(original / name, retained, row['changed_resources'] if name in active else [])
        resource_checks[name] = ok
    core = json.loads((directory / 'component-results.json').read_text())
    fresh_core = all(sha(directory / name) == digest for name, digest in core['evidence_sha256'].items())
    checks = {
        'native_milestone_and_network_gates': core['passed'] and fresh_core,
        'fresh_service_shutdown_fixture': text.rfind('SHUTDOWN_PROOF_CLEARED') > text.rfind('SERVICE_PROBE_EXIT=') >= 0,
        'branding_probe_cases': len(rows) == len(cases) and all(row.get('status') == 'pass' for row in rows.values()),
        'branding_probe_exit_zero': end >= 0 and text[end:].splitlines()[0].strip() == 'BRANDING_PROBE_EXIT=0',
        'version_api_identity_matches_baseline': len(identity) == 1 and identity == base_identity,
        'protected_registry_identity_matches_baseline': (retention / 'xp25/branding-identity.bin').read_bytes() ==
            (baseline / 'retention/xp25/branding-identity.bin').read_bytes(),
        'cmd_version_matches_baseline': (retention / 'xp25/cmd-version.txt').read_bytes() ==
            (baseline / 'retention/xp25/cmd-version.txt').read_bytes(),
        'source_smss_retained': (retention / 'WINDOWS/system32/smss.exe').read_bytes() ==
            (baseline / 'retention/WINDOWS/system32/smss.exe').read_bytes(),
        'msi_install_uninstall_and_state': 'MSI_FIXTURE_FINISHED' in msi and all(
            [line.strip() for line in msi.splitlines() if line.startswith(name + '=')] == [name + '=0']
            for name in ('MSI_BUILD_EXIT', 'MSI_INSTALL_EXIT', 'MSI_INSTALLED_STATE_EXIT',
                         'MSI_UNINSTALL_EXIT', 'MSI_UNINSTALLED_STATE_EXIT')),
        'reviewed_resources_retained': all(resource_checks.values()),
        'original_ui_recovery_retained': all(
            (retention / 'xp25' / ('brand-original-' + Path(name).name)).is_file() and
            sha(retention / 'xp25' / ('brand-original-' + Path(name).name)) == manifest['components'][name]['original_sha256']
            for name in active),
        'normal_shutdown_frozen': json.loads((directory / 'checkpoint.json').read_text())['stage'] == 'normal_shutdown_frozen' and
            not bool((directory / 'disk.qcow2').stat().st_mode & 0o222) and
            sha(directory / 'disk.qcow2') == json.loads((directory / 'checkpoint.json').read_text())['disk_sha256'],
    }
    if args.notepad_marker:
        checks['unique_notepad_readback'] = (retention / 'xp25/component-notepad.txt').read_bytes() == args.notepad_marker.encode('ascii')
    files = [directory / name for name in ('serial.log', 'component-results.json', 'normal-shutdown.json',
             'checkpoint.json', 'retention/files.json')]
    files += [path for path in retention.rglob('*') if path.is_file()]
    result = {'passed': all(checks.values()), 'stage': args.stage, 'baseline': str(baseline),
              'package': str(package), 'checks': checks, 'observations': rows, 'identity': identity,
              'resource_checks': resource_checks,
              'historical_branding_failures': [line for line in text.splitlines() if '"branding_case"' in line and '"fail"' in line],
              'limits': ['GUI screenshots require separate review.', 'Recorded en-US VM fixtures only; no general application compatibility claim.'],
              'evidence_sha256': {str(p.relative_to(directory)): sha(p) for p in files}}
    (directory / 'branding-results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'experiment': directory.name, 'passed': result['passed'], 'checks': checks}))
    return 0 if result['passed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
