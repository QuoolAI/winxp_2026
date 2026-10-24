#!/usr/bin/env python3
"""Require complete SCM behavior, image identity, retention and shutdown evidence."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build'))
from inspect_component import PE

CASES = ('scm_manager_access', 'fixture_names_unused', 'create_service_pair',
         'dependency_configuration', 'dependent_start_starts_prerequisite',
         'active_dependency_stop_rejected', 'dependent_stop', 'prerequisite_stop',
         'service_restart', 'restarted_service_stop', 'delete_dependent',
         'delete_prerequisite', 'fixture_cleanup', 'service_probe_complete')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--expected-scm', type=Path, required=True)
    parser.add_argument('--expected-component', type=Path, help='additional individually installed component')
    parser.add_argument('--guest-target', help='absolute path of that additional component')
    args = parser.parse_args()
    if bool(args.expected_component) != bool(args.guest_target):
        parser.error('expected component and guest target must be supplied together')
    directory = args.directory.resolve()
    if not directory.is_relative_to(ROOT / '.work'):
        parser.error('runtime evidence must remain under private .work/')
    if args.guest_target and not re.fullmatch(r'/WINDOWS/(system32/[A-Za-z0-9_]+\.(exe|dll)|explorer\.exe)', args.guest_target):
        parser.error('an explicit system32 EXE/DLL or Explorer guest target is required')
    result_path = directory / 'component-results.json'
    if result_path.exists():
        previous = result_path.read_bytes()
        (directory / ('component-results.previous-' + hashlib.sha256(previous).hexdigest()[:12] + '.json')).write_bytes(previous)
        result_path.unlink()
    subprocess.run([sys.executable, str(ROOT / 'vm/network_results.py'), str(directory)], check=True)
    text = (directory / 'serial.log').read_text(errors='replace')
    end = text.rfind('SERVICE_PROBE_EXIT=')
    start = text.rfind('SERVICE_PROBE_STARTED', 0, end)
    observations = []
    for line in text[start:end].splitlines() if start >= 0 else []:
        try:
            observations.append(json.loads(line))
        except ValueError:
            pass
    rows = {row['case']: row for row in observations if row.get('case') in CASES}
    identity = [row for row in observations if row.get('event') == 'scm_image_identity']
    expected = PE(args.expected_scm).inspect()
    retention = directory / 'retention'
    scm = retention / 'WINDOWS/system32/services.exe'
    proof = retention / 'xp25/service-shutdown.txt'
    inputs = json.loads((directory / 'inputs.json').read_text())
    recovery = inputs.get('recovery')
    backup_ok = True
    if recovery:
        backup = retention / recovery['guest_backup'].lstrip('/')
        backup_ok = backup.is_file() and hashlib.sha256(backup.read_bytes()).hexdigest() == recovery['original_sha256']
    checks = {
        'network_and_existing_regressions': json.loads((directory / 'network-results.json').read_text())['automated_gates_passed'],
        'service_behavior': len(rows) == len(CASES) and all(row.get('status') == 'pass' for row in rows.values()),
        'service_exit_zero': end >= 0 and text[end:].splitlines()[0].strip() == 'SERVICE_PROBE_EXIT=0',
        'live_scm_checksum': len(identity) == 1 and identity[0].get('read') is True and
                             identity[0].get('pe_checksum') == int(expected['checksum_stored'], 16),
        'component_retained': scm.is_file() and hashlib.sha256(scm.read_bytes()).hexdigest() == expected['sha256'],
        'original_component_recovery_retained': backup_ok,
        'shutdown_fixture_armed': [line.strip() for line in text.splitlines()
                                   if line.startswith('SHUTDOWN_PROBE_EXIT=')][-1:] == ['SHUTDOWN_PROBE_EXIT=0'],
        'service_received_shutdown': proof.is_file() and proof.read_bytes() == b'SCM_SERVICE_CONTROL_SHUTDOWN\r\n',
        'loaded_source_kernel': json.loads((directory / 'native-stack-verification.json').read_text())['checksum_matches'],
    }
    if args.expected_component:
        retained = retention / args.guest_target.lstrip('/')
        checks['additional_component_retained'] = retained.is_file() and retained.read_bytes() == args.expected_component.read_bytes()
        checks['fresh_shutdown_proof'] = text.rfind('SHUTDOWN_PROOF_CLEARED') > end >= 0
    evidence = [directory / name for name in ('serial.log', 'inputs.json', 'checkpoint.json',
        'normal-shutdown.json', 'native-stack-verification.json', 'network-results.json',
        'network-isolation.json', 'dnsmasq.log', 'http.jsonl')]
    evidence += [scm, proof]
    if recovery:
        evidence.append(backup)
    if args.expected_component:
        evidence.append(retained)
    result = {'checks': checks, 'passed': all(checks.values()), 'expected_scm': expected,
              'live_scm': identity, 'service_observations': rows, 'recovery': recovery,
              'evidence_sha256': {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
                                  for path in evidence if path.is_file()}}
    result_path.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'experiment': directory.name, 'passed': result['passed'], 'checks': checks}))
    return 0 if result['passed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
