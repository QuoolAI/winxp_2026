#!/usr/bin/env python3
"""Decide the gates of one finished XP25 security-lab run (vm/security_lab.py).

Inputs are the guest's own records: COM1 markers and probe cases, the JSON
lines files it wrote to C:\\xp25sec (read from the frozen disk, never from a
running guest), the QMP shutdown event and the namespace-side port scans.
Screenshots are not consulted. The result is results.json in the run
directory; the exit code is 0 only when every gate of the run's role passed.

usage: security_results.py RUN"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / '.work/security-20261111/runs'
COMPAT_EXITS = ('STANDARD_PROBE_EXIT', 'POINTER_PROBE_EXIT', 'SESSION_PROBE_EXIT', 'NETWORK_PROBE_EXIT', 'SERVICE_PROBE_EXIT',
                'REGSVC_PROBE_EXIT', 'GINA_PROBE_EXIT', 'USERENV_PROBE_EXIT', 'BRANDING_PROBE_EXIT', 'MSI_BUILD_EXIT',
                'MSI_INSTALL_EXIT', 'MSI_INSTALLED_STATE_EXIT', 'MSI_UNINSTALL_EXIT', 'MSI_UNINSTALLED_STATE_EXIT',
                'SHELL_PROBE_EXIT', 'PROFILE_PROBE_EXIT')
WORK_FILES = {
    'audit': ['status-before', 'enumerate-before', 'plan-before', 'verify-before', 'audit-before'],
    'harden': ['enumerate-before', 'plan', 'apply', 'verify-before-restart', 'status-hardened', 'enumerate-hardened',
               'verify-hardened', 'audit-hardened', 'snapshot-hardened', 'audit-clean-hardened', 'audit-drift-hardened',
               'reapply-drift-hardened', 'reapply-hardened', 'verify-final-hardened', 'audit-final-hardened'],
    'proof': ['status-proof', 'enumerate-proof', 'verify-proof', 'audit-proof', 'audit-clean-proof', 'audit-drift-proof',
              'reapply-drift-proof', 'reapply-proof', 'verify-final-proof', 'audit-final-proof'],
    'rollback': ['status-before-rollback', 'rollback', 'status-rolled-back', 'enumerate-rolled-back', 'verify-rolled-back',
                 'audit-rolled-back'],
    'regression': [], 'image-install': [],
}
STORE_FILES = ['install-apply.jsonl', 'install-services-before.jsonl', 'install-plan.jsonl', 'install-verify.jsonl',
               'install-snapshot.jsonl', 'install-audit.jsonl', 'baseline-backup.txt', 'audit-snapshot.txt']


def rows(path):
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text('utf-8', 'replace').splitlines() if line.strip().startswith('{')]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('run')
    args = parser.parse_args()
    run = RUNS / args.run
    inputs = json.loads((run / 'inputs.json').read_text())
    role, mode = inputs['role'], inputs['mode']
    serial = (run / 'serial.log').read_bytes().decode('utf-8', 'replace').replace('\r', '')
    lines = serial.splitlines()
    gates = []

    def gate(name, passed, detail=''):
        gates.append({'gate': name, 'passed': bool(passed), 'detail': str(detail)[:600]})

    def marker(name):
        found = re.findall(r'^' + re.escape(name) + r'=(-?\d+)', serial, re.M)
        return [int(x) for x in found]

    # Result files from the frozen disk.
    results = Path(str(run) + '-results')
    disk = run / 'disk.qcow2'
    if not results.exists() and disk.exists() and not disk.stat().st_mode & 0o222:
        wanted = ['/xp25sec/%s.jsonl' % name for name in WORK_FILES[role]]
        wanted += ['/WINDOWS/XP25/Security/' + name for name in STORE_FILES]
        wanted += ['/xp25sec/firewall-%s.txt' % tag for tag in ('before', 'hardened', 'proof', 'rolled-back')]
        wanted += ['/Documents and Settings/XP25/xp25sec-security_probe.exe', '/Documents and Settings/XP25/xp25sec-suite.cmd',
                   '/xp25sec/phase1.done']
        subprocess.run([sys.executable, str(ROOT / 'vm/read_guest.py'), str(disk), str(results)] + wanted, capture_output=True)
    work = results / 'xp25sec'
    store = results / 'WINDOWS/XP25/Security'
    extracted = {row['guest_path']: row for row in json.loads((results / 'files.json').read_text())['files']} \
        if (results / 'files.json').is_file() else {}

    # Every role: the session came up under the expected logon process and the guest powered itself off.
    event = json.loads((run / 'guest-shutdown-event.json').read_text()) if (run / 'guest-shutdown-event.json').is_file() else {}
    checkpoint = json.loads((run / 'checkpoint.json').read_text())
    gate('guest_requested_shutdown', event.get('data') == {'guest': True, 'reason': 'guest-shutdown'} and
         checkpoint.get('stage') == 'normal_shutdown_frozen', event.get('data'))
    boots = 2 if role in ('harden', 'image-install', 'rollback') else 1
    if inputs.get('xp25_winlogon'):
        events = re.findall(r'\{"xp25_winlogon":"([^"]+)"', serial)
        gate('xp25_winlogon_logon_each_boot', events.count('core_ready') == boots and events.count('session_interactive') == boots and
             events.count('licensing_policy_allowed') == boots and events.count('explorer_token_identity_verified') >= boots,
             {name: events.count(name) for name in ('core_ready', 'session_interactive', 'licensing_policy_allowed',
                                                    'explorer_token_identity_verified')})
        gate('no_winlogon_failure_record', not [e for e in events if e.endswith('_failed') and e != 'lock_request_failed'],
             [e for e in events if e.endswith('_failed')][:5])
    gate('suite_completed', 'XP25_SEC_SUITE_DONE' in serial)

    hardened = role in ('harden', 'proof')
    if role in ('regression', 'harden', 'proof'):
        ai = re.findall(r'AI_PROBE_COMPLETE passes=(\d+) failures=(\d+)', serial)
        gate('ai_suite_55_cases', len(ai) >= 1 and ai[0] == ('55', '0') and marker('XP25_AI_PROBE_EXIT') == [0], ai[:1])
        gate('ai_provider_7_cases', len(ai) >= 2 and ai[1] == ('7', '0') and marker('XP25_AI_PROVIDER_EXIT') == [0], ai[1:2])
        exits = {name: marker(name) for name in COMPAT_EXITS}
        gate('established_compatibility_suite', all(values and values[-1] == 0 for values in exits.values()),
             {name: values for name, values in exits.items() if not values or values[-1] != 0})
        # Failed cases anywhere in the serial log; with the baseline only the bracketed Remote Registry refusal may fail.
        failed, refused, inside = [], [], False
        for line in lines:
            if 'XP25_SEC_REGSVC_REFUSED_START' in line:
                inside = True
            elif 'XP25_SEC_REGSVC_REFUSED_END' in line:
                inside = False
            elif '"status":"fail' in line or '"passed":false' in line:
                (refused if inside else failed).append(line.strip()[:200])
        gate('no_failed_probe_case', not failed, failed[:4])
        if hardened:
            gate('disabled_remote_registry_refuses_unchanged_probe',
                 any('"regsvc_case":"service_start"' in line and '"error":1058' in line for line in refused) and
                 marker('REGSVC_PROBE_WHILE_DISABLED_EXIT') == [1], refused[:2])
            gate('administrator_can_reenable_and_baseline_reapplies', marker('XP25_SEC_REMOTE_REGISTRY_ENABLED_BY_ADMIN') == [0] and
                 marker('REGSVC_PROBE_EXIT') == [0] and marker('XP25_SEC_REAPPLY_EXIT') == [0])

    if role in ('harden', 'image-install'):
        gate('tools_installed', marker('XP25_SEC_INSTALL_SEC') == [0] and marker('XP25_SEC_INSTALL_AUDIT') == [0])
        gate('baseline_applied_without_failure', marker('XP25_SEC_APPLY_EXIT') == [0] and marker('XP25_SEC_VERIFY_BEFORE_RESTART_EXIT') == [0])
    if role in ('harden', 'image-install', 'proof'):
        gate('baseline_verified_after_restart', marker('XP25_SEC_VERIFY_EXIT') == [0])
        gate('baseline_verified_after_workload', marker('XP25_SEC_FINAL_VERIFY_EXIT') == [0])
    if hardened:
        tag = 'hardened' if role == 'harden' else 'proof'
        verify = rows(work / ('verify-%s.jsonl' % tag))
        gate('verify_records_all_ok', verify and all(row.get('ok', True) for row in verify),
             [row.get('id') for row in verify if row.get('ok') is False][:6])
        services = [row for row in rows(work / ('enumerate-%s.jsonl' % tag)) if row.get('kind') == 'service']
        managed = [row for row in services if row.get('managed')]
        gate('managed_services_disabled_and_stopped', managed and all(row.get('compliant') for row in managed),
             [row['name'] for row in managed if not row.get('compliant')])
        before = [row for row in rows(work / 'enumerate-before.jsonl') or rows(store / 'install-services-before.jsonl')
                  if row.get('kind') == 'service']
        if before:
            was = sorted(row['name'] for row in before if row.get('managed') and row.get('state') == 'running')
            now = sorted(row['name'] for row in managed if row.get('state') == 'running')
            gate('fewer_services_running', len(was) > 0 and not now, {'managed_running_before': was, 'managed_running_after': now,
                 'all_running_before': sum(row.get('state') == 'running' for row in before),
                 'all_running_after': sum(row.get('state') == 'running' for row in services)})
        probe = re.findall(r'SECURITY_PROBE_COMPLETE context=(\w+) passes=(\d+) failures=(\d+) observed=(\d+) not_run=(\d+)', serial)
        gate('security_probe_ordinary_account', any(p[0] == 'ordinary_account' and p[2] == '0' and int(p[1]) >= 60 for p in probe), probe)
        gate('security_probe_restricted_token', any(p[0] == 'restricted_token' and p[2] == '0' and int(p[1]) >= 60 for p in probe), probe)
        gate('security_probe_administrator', any(p[0] == 'admin' and p[2] == '0' and int(p[1]) >= 30 for p in probe) and
             marker('XP25_SEC_PROBE_EXIT') == [0], probe)
        skipped = [json.loads(line[line.index('{'):]).get('security_case') + '/' + json.loads(line[line.index('{'):]).get('context')
                   for line in lines if '"security_case"' in line and '"status":"not_run"' in line]
        # Cases whose object legitimately does not exist: the snapshot is recorded after the probe in the
        # harden role, and the agent policy key exists only after an administrator sets a policy.
        allowed = {'open_audit_snapshot_for_write', 'change_acl_of_xp25_agent_policy'} if role == 'harden' else {'change_acl_of_xp25_agent_policy'}
        gate('security_probe_no_unexplained_skip', all(name.split('/')[0] in allowed for name in skipped), skipped)
        for case in ('audit_records_account_management', 'audit_records_failed_logon', 'disabled_service_does_not_start',
                     'administrator_cannot_open_winlogon_desktop', 'run_as_ordinary_account', 'wrong_password_rejected'):
            gate('probe_case_' + case, any('"security_case":"%s"' % case in line and '"status":"pass"' in line for line in lines))
        audit = rows(work / ('audit-%s.jsonl' % tag))
        summary = next((row for row in audit if row.get('kind') == 'summary'), {})
        firewall = next((row for row in audit if row.get('kind') == 'firewall'), {})
        gate('audit_report_completed_read_only', summary.get('read_only') is True and marker('XP25_SEC_AUDIT_EXIT') == [0] and
             not summary.get('records_dropped'), {k: summary.get(k) for k in ('findings_high', 'findings_medium', 'findings_low',
                                                                             'unreadable_sources', 'records')})
        gate('firewall_reports_enabled', firewall.get('state_known') and firewall.get('enabled'), firewall)
        gate('audit_finds_no_high_severity_issue', summary.get('findings_high') == 0,
             [(row['rule'], row['subject'][-60:]) for row in audit if row.get('kind') == 'finding' and row.get('severity') == 'high'][:6])
        clean = {(row['rule'], row['subject']) for row in rows(work / ('audit-clean-%s.jsonl' % tag)) if row.get('kind') == 'finding'}
        drift = {(row['rule'], row['subject']) for row in rows(work / ('audit-drift-%s.jsonl' % tag)) if row.get('kind') == 'finding'}
        expected = {('config.added', 'autostart:HKLM\\run\\XP25SecDriftTest'), ('config.changed', 'service:RemoteRegistry'),
                    ('service.baseline_deviation', 'RemoteRegistry')}
        gate('audit_detects_deliberate_changes', expected <= drift and not (expected & clean) and marker('XP25_SEC_DRIFT_REAPPLY_EXIT') == [0],
             {'missing': sorted(expected - drift), 'present_before_change': sorted(expected & clean)})
        final = rows(work / ('audit-final-%s.jsonl' % tag))
        gate('audit_clean_after_repair', not ({(row['rule'], row['subject']) for row in final if row.get('kind') == 'finding'} & expected))
    if role in ('audit', 'harden', 'proof', 'rollback'):
        label = {'audit': 'before', 'harden': 'hardened', 'proof': 'proof', 'rollback': 'rolled-back'}[role]
        scan = json.loads((run / ('scan-result-%s.json' % label)).read_text()) if (run / ('scan-result-%s.json' % label)).is_file() else None
        check = json.loads((run / ('scan-check-%s.json' % label)).read_text()) if (run / ('scan-check-%s.json' % label)).is_file() else {}
        if scan is None:
            gate('external_scan_performed', False)
        else:
            answered = sorted(port for port, state in scan['udp'].items() if state['state'] == 'response')
            burst = scan.get('udp_137_burst')
            detail = {'tcp_open': scan['tcp_open'], 'tcp_filtered': scan['tcp_filtered_count'], 'tcp_closed': scan['tcp_closed_count'],
                      'udp_answered': answered, 'udp_137_burst': burst, 'icmp_echo_reply': scan['icmp_echo_reply'],
                      'inside_scan_window': check.get('inside_window')}
            if role == 'audit':
                gate('external_scan_recorded', True, detail)
            elif role == 'rollback':
                # Rollback restores the original firewall settings, so the broadcast-response window is open
                # again exactly as before hardening: the name service answers while the guest broadcasts.
                # Unsolicited TCP stays filtered, because the kernel export that lets the firewall run is
                # not part of the tool's rollback.
                gate('original_firewall_behaviour_restored', burst is not None and burst['answers'] > 0 and not scan['tcp_open'], detail)
            else:
                # The name-service burst runs while the guest itself broadcasts from UDP 137; a scan without it proves less.
                gate('nothing_reachable_from_the_network', not scan['tcp_open'] and not answered and not scan['icmp_echo_reply'] and
                     scan['tcp_filtered_count'] == scan['tcp_ports_probed'] and burst is not None and burst['answers'] == 0, detail)
            if check:
                gate('scan_ran_while_guest_was_up', check.get('inside_window') is True, check)
    if role == 'image-install':
        gate('reference_snapshot_recorded', marker('XP25_SEC_SNAPSHOT_EXIT') == [0])
        gate('test_payload_removed', marker('XP25_SEC_WORKDIR_REMOVED') == [0] and
             'error' in extracted.get('/Documents and Settings/XP25/xp25sec-security_probe.exe', {'error': 1}) and
             'error' in extracted.get('/Documents and Settings/XP25/xp25sec-suite.cmd', {'error': 1}) and
             'error' in extracted.get('/xp25sec/phase1.done', {'error': 1}))
        verify = rows(store / 'install-verify.jsonl')
        gate('install_record_kept_in_store', verify and all(row.get('ok', True) for row in verify) and rows(store / 'install-apply.jsonl') and
             (store / 'baseline-backup.txt').is_file() and (store / 'audit-snapshot.txt').is_file())
    if role == 'rollback':
        gate('rollback_completed', marker('XP25_SEC_ROLLBACK_EXIT') == [0])
        rolled = rows(work / 'rollback.jsonl')
        gate('rollback_records_all_restored', rolled and not [row for row in rolled if row.get('result') == 'failed'],
             [row.get('id') for row in rolled if row.get('result') == 'failed'][:6])
        status = (rows(work / 'status-rolled-back.jsonl') or [{}])[0]
        gate('baseline_reported_absent', status.get('baseline_applied') is False and status.get('backup_present') is False, status)
        gate('verify_reports_deviations', bool(marker('XP25_SEC_VERIFY_AFTER_ROLLBACK_EXIT')) and marker('XP25_SEC_VERIFY_AFTER_ROLLBACK_EXIT')[0] > 0,
             marker('XP25_SEC_VERIFY_AFTER_ROLLBACK_EXIT'))
        original = {row['name']: row.get('start') for row in rows(store / 'install-services-before.jsonl') if row.get('managed')}
        current = {row['name']: row.get('start') for row in rows(work / 'enumerate-rolled-back.jsonl') if row.get('managed')}
        gate('service_start_types_restored', original and original == current,
             {name: (original.get(name), current.get(name)) for name in original if original.get(name) != current.get(name)})
        gate('remote_registry_works_again', marker('REGSVC_PROBE_EXIT') == [0])

    record = {'run': args.run, 'role': role, 'mode': mode, 'kernel': inputs.get('kernel'), 'base_sha256': inputs['base_sha256'],
              'staged': {target: item['sha256'] for target, item in inputs['staged'].items()},
              'disk_sha256': checkpoint.get('disk_sha256'), 'serial_sha256': hashlib.sha256((run / 'serial.log').read_bytes()).hexdigest(),
              'gates': gates, 'all_passed': all(g['passed'] for g in gates)}
    (run / 'results.json').write_text(json.dumps(record, indent=1) + '\n')
    for g in gates:
        print(('PASS ' if g['passed'] else 'FAIL ') + g['gate'] + ('' if g['passed'] or not g['detail'] else '  ' + g['detail'][:300]))
    print('ALL_PASSED' if record['all_passed'] else 'SOME_FAILED', '%d gates' % len(gates))
    return 0 if record['all_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
