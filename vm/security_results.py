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
sys.path.insert(0, str(ROOT / 'vm'))
import security_fixtures
import security_paths
import security_pcap

RUNS = security_paths.RUNS
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
    'firewall': ['verify-fw-boot1', 'verify-fw-boot2'],
    'ai-repeat': [], 'image-upgrade': [], 'apps': ['apps-admin'], 'cve': [],
    'standard-user': ['std-desktop-1', 'std-apps-1', 'std-desktop-2'],
}
FIREWALL_TEXT = ['fw-sc-qc', 'fw-sc-sdshow', 'fw-sc-ipnat-qc', 'fw-sc-query-boot1', 'fw-sc-ipnat-boot1', 'fw-state-boot1', 'fw-config-boot1',
                 'fw-sc-query-boot2', 'fw-sc-ipnat-boot2', 'fw-state-boot2', 'fw-config-boot2', 'fw-admin-add-tcp', 'fw-admin-add-udp',
                 'fw-admin-delete-tcp', 'fw-admin-delete-udp', 'fw-admin-disable', 'fw-admin-enable', 'fw-admin-stop', 'fw-admin-start']
# Programs that crash when closed on the unhardened combined base as well (run apps-base-up-01):
# compatibility defects of that base, not regressions of the baseline.
KNOWN_CRASHES = {'game_hearts_closes_without_crashing'}
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
        if role == 'firewall':
            wanted += ['/xp25sec/%s.txt' % name for name in FIREWALL_TEXT] + ['/xp25sec/listener.jsonl']
        if role == 'proof':
            wanted += ['/xp25sec/apps-proof.jsonl']
        if role == 'standard-user':
            wanted += ['/xp25sec/%s.txt' % name for name in ('std-account', 'std-groups-users', 'std-groups-admins', 'std-whoami-1', 'std-whoami-2')]
        if role == 'image-upgrade':
            wanted += ['/WINDOWS/XP25/Security/upgrade-81-%s.jsonl' % name for name in ('apply', 'services-before', 'plan', 'verify', 'snapshot', 'audit')]
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
    boots = 3 if role == 'standard-user' else 2 if role in ('harden', 'image-install', 'image-upgrade', 'rollback', 'firewall') else 1
    sessions = len(inputs.get('logons') or []) or boots
    if inputs.get('xp25_winlogon'):
        events = re.findall(r'\{"xp25_winlogon":"([^"]+)"', serial)
        gate('xp25_winlogon_logon_each_boot', events.count('core_ready') == boots and events.count('session_interactive') == sessions and
             events.count('licensing_policy_allowed') == sessions and events.count('explorer_token_identity_verified') >= sessions,
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
                # A crash the unhardened base shows as well is judged by no_program_crash_beyond_the_unhardened_base.
                if any('"security_case":"%s"' % known in line for known in KNOWN_CRASHES):
                    continue
                (refused if inside else failed).append(line.strip()[:200])
        gate('no_failed_probe_case', not failed, failed[:4])
        if hardened:
            gate('disabled_remote_registry_refuses_unchanged_probe',
                 any('"regsvc_case":"service_start"' in line and '"error":1058' in line for line in refused) and
                 marker('REGSVC_PROBE_WHILE_DISABLED_EXIT') == [1], refused[:2])
            gate('administrator_can_reenable_and_baseline_reapplies', marker('XP25_SEC_REMOTE_REGISTRY_ENABLED_BY_ADMIN') == [0] and
                 marker('REGSVC_PROBE_EXIT') == [0] and marker('XP25_SEC_REAPPLY_EXIT') == [0])

    if role in ('harden', 'image-install', 'image-upgrade'):
        gate('tools_installed', marker('XP25_SEC_INSTALL_SEC') == [0] and marker('XP25_SEC_INSTALL_AUDIT') == [0])
        gate('baseline_applied_without_failure', marker('XP25_SEC_APPLY_EXIT') == [0] and marker('XP25_SEC_VERIFY_BEFORE_RESTART_EXIT') == [0])
    if role in ('harden', 'image-install', 'image-upgrade', 'proof'):
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
        # The broker's former audit file under All Users exists only where a Milestone 8 broker ran.
        allowed = {'change_acl_of_xp25_agent_policy', 'open_broker_audit_trail_for_write'}
        if role == 'harden':
            allowed.add('open_audit_snapshot_for_write')
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
    capture = security_pcap.summarize(run / 'network.pcap') if (run / 'network.pcap').is_file() else {'segments': {}}
    (run / 'pcap-summary.json').write_text(json.dumps(capture, indent=1) + '\n')

    def observation(label):
        path = run / ('scan-result-%s.json' % label)
        return json.loads(path.read_text()) if path.is_file() else None

    if role == 'firewall':
        probe = re.findall(r'SECURITY_PROBE_COMPLETE context=(\w+) passes=(\d+) failures=(\d+) observed=(\d+) not_run=(\d+)', serial)
        failed_cases = [json.loads(line[line.index('{'):]) for line in lines if '"security_case"' in line and '"status":"fail"' in line]

        def checked(context):
            return any(p[0] == context and p[2] == '0' and int(p[1]) >= 8 for p in probe)
        # Guest-observed state.
        gate('firewall_service_and_driver_running_first_boot', checked('firewall_boot1') and marker('XP25_FW_CHECK_BOOT1') == [0],
             [c for c in failed_cases if c['context'] == 'firewall_boot1'])
        gate('firewall_service_and_driver_running_after_restart', checked('firewall_boot2') and marker('XP25_FW_CHECK_BOOT2') == [0],
             [c for c in failed_cases if c['context'] == 'firewall_boot2'])
        gate('firewall_still_running_after_unprivileged_attempts', checked('firewall_after_unprivileged') and
             marker('XP25_FW_CHECK_AFTER_UNPRIVILEGED') == [0], [c for c in failed_cases if c['context'] == 'firewall_after_unprivileged'])
        gate('unprivileged_firewall_attempts_all_refused',
             any(p[0] == 'ordinary_account' and p[2] == '0' for p in probe) and any(p[0] == 'restricted_token' and p[2] == '0' for p in probe) and
             marker('XP25_SEC_PROBE_EXIT') == [0],
             [(c['security_case'], c['context'], c['note'][:60]) for c in failed_cases if c['context'] in ('ordinary_account', 'restricted_token', 'admin')][:8])
        not_run = [json.loads(line[line.index('{'):]) for line in lines if '"security_case"' in line and '"status":"not_run"' in line]
        gate('no_firewall_case_skipped', not [c for c in not_run if 'firewall' in c['security_case'] or 'netsh' in c['security_case']],
             [(c['security_case'], c['context'], c['note'][:50]) for c in not_run][:8])
        # Administrator management.
        commands = ('ADMIN_ADD_TCP', 'ADMIN_ADD_UDP', 'ADMIN_DELETE_TCP', 'ADMIN_DELETE_UDP', 'ADMIN_DISABLE', 'ADMIN_ENABLE', 'ADMIN_STOP', 'ADMIN_START')
        gate('administrator_firewall_commands_succeed', all(marker('XP25_FW_' + name) == [0] for name in commands),
             {name: marker('XP25_FW_' + name) for name in commands if marker('XP25_FW_' + name) != [0]})
        gate('baseline_verified_after_administrator_restored_it', marker('XP25_FW_VERIFY_BOOT1') == [0] and marker('XP25_SEC_FINAL_VERIFY_EXIT') == [0],
             {'after_admin': marker('XP25_FW_VERIFY_BOOT1'), 'after_restart': marker('XP25_SEC_FINAL_VERIFY_EXIT')})
        # Host-observed enforcement, each stage from the observer's sockets and again from the packet capture.
        port = str(security_fixtures.LISTENER_PORT)

        def blocked(label, broadcasting=True, datagrams=True):
            seen, wire = observation(label), capture['segments'].get(label)
            if not seen or not wire or 'tcp' not in seen:
                return False, {'observation': bool(seen), 'capture_segment': bool(wire)}
            ok = (all(state['state'] == 'filtered' for state in seen['tcp'].values()) and
                  (not datagrams or (seen['udp_listener']['state'] == 'no_response' and not wire['udp_replies_from_guest'])) and
                  seen['udp_137_burst']['answers'] == 0 and not seen['icmp_echo_reply'] and
                  wire['tcp_syn_to_guest'].get(port, 0) > 0 and not wire['tcp_synack_from_guest'] and not wire['tcp_rst_from_guest'] and
                  not wire['udp_replies_from_guest'].get('137') and not wire['icmp_echo_reply_from_guest'] and not wire['icmp_unreachable_from_guest'] and
                  (not broadcasting or wire['guest_broadcast_udp'].get(port, 0) > 0))
            return ok, {'tcp': {k: v['state'] for k, v in seen['tcp'].items()}, 'udp_listener': seen['udp_listener']['state'],
                        'name_service_answers': '%d/%d' % (seen['udp_137_burst']['answers'], seen['udp_137_burst']['probes']),
                        'icmp_echo_reply': seen['icmp_echo_reply'], 'wire_syn_to_listener': wire['tcp_syn_to_guest'].get(port, 0),
                        'wire_synack': wire['tcp_synack_from_guest'], 'wire_rst': wire['tcp_rst_from_guest'],
                        'wire_udp_replies': wire['udp_replies_from_guest'], 'wire_guest_name_broadcasts': wire['guest_broadcast_udp'].get('137', 0),
                        'wire_guest_listener_broadcasts': wire['guest_broadcast_udp'].get(port, 0)}

        def reachable(label):
            seen, wire = observation(label), capture['segments'].get(label)
            if not seen or not wire or 'tcp' not in seen:
                return False, {'observation': bool(seen), 'capture_segment': bool(wire)}, {}
            ok = (seen['listener_tcp_reachable'] and seen['listener_udp_reachable'] and wire['tcp_synack_from_guest'].get(port, 0) > 0 and
                  wire['udp_replies_from_guest'].get(port, 0) > 0)
            detail = {'listener_tcp': seen['tcp'][port], 'listener_udp': seen['udp_listener'],
                      'other_tcp': {k: v['state'] for k, v in seen['tcp'].items() if k != port},
                      'name_service_answers': '%d/%d' % (seen['udp_137_burst']['answers'], seen['udp_137_burst']['probes']),
                      'icmp_echo_reply': seen['icmp_echo_reply'], 'wire_synack': wire['tcp_synack_from_guest'],
                      'wire_udp_replies': wire['udp_replies_from_guest']}
            return ok, detail, seen

        # Right after the exception is removed, new connections are refused; what the firewall still
        # holds for the earlier datagram conversation is measured by the series that follows.
        ok, detail = blocked('removed', datagrams=False)
        gate('new_connections_blocked_as_soon_as_exception_is_removed', ok, detail)
        expiry = observation('removed-expiry') or {}
        # Recorded, not judged: whether the firewall still held state for the port right after the removal.
        gate('removed_exception_state_ends_for_every_peer', expiry.get('kind') == 'udp-expiry' and
             expiry.get('after_quiet_known_peer') == 'no_response' and expiry.get('after_quiet_new_peer') == 'no_response' and
             expiry.get('tcp_listener', {}).get('state') == 'filtered',
             {k: expiry.get(k) for k in ('immediately_after_removal', 'quiet_seconds', 'after_quiet_known_peer', 'after_quiet_new_peer', 'tcp_listener')})
        for label, name in (('blocked', 'listener_blocked_without_exception'),
                            ('after-unprivileged', 'listener_blocked_after_unprivileged_attempts'),
                            ('admin-enabled', 'listener_blocked_after_administrator_reenabled_firewall'),
                            ('service-started', 'listener_blocked_after_service_restart'), ('after-restart', 'listener_blocked_after_guest_restart')):
            ok, detail = blocked(label)
            gate(name, ok, detail)
        ok, detail, seen = reachable('permitted')
        # The exception is for one port: everything else stays filtered and the name service stays silent.
        gate('explicitly_permitted_port_works', ok and all(state == 'filtered' for state in detail.get('other_tcp', {}).values()) and
             seen.get('udp_137_burst', {}).get('answers') == 0 and not seen.get('icmp_echo_reply'), detail)
        ok, detail, seen = reachable('admin-disabled')
        gate('same_listener_reachable_when_administrator_disables_firewall', ok, detail)
        ok, detail, seen = reachable('service-stopped')
        gate('same_listener_reachable_when_service_is_stopped', ok, detail)
        watch = observation('restart') or {}
        wire = capture['segments'].get('restart', {})
        # The guest asked for its address again inside the watched period: the watch spans the restart.
        restarted = wire.get('dhcp_requests_without_address', 0) > 0 or wire.get('guest_broadcast_udp', {}).get('67', 0) > 0
        gate('nothing_answered_at_any_moment_of_the_restart', watch.get('kind') == 'watch' and not watch.get('answers') and
             restarted and watch.get('ticks', 0) > 40 and not watch.get('error'),
             {'answers': watch.get('answers'), 'seconds': watch.get('seconds'), 'ticks': watch.get('ticks'), 'guest_restarted_inside': restarted,
              'first_answers': [row for row in watch.get('transitions', []) if row['state'] in ('open', 'closed', 'response', 'reply')][:6],
              'error': watch.get('error')})
        gate('capture_confirms_restart_window', bool(wire) and restarted and not wire.get('tcp_synack_from_guest') and
             not wire.get('tcp_rst_from_guest') and not wire.get('udp_replies_from_guest') and not wire.get('icmp_echo_reply_from_guest') and
             wire.get('tcp_syn_to_guest', {}).get('135', 0) > 20 and wire.get('udp_to_guest', {}).get('137', 0) > 40,
             {k: wire.get(k) for k in ('tcp_syn_to_guest', 'udp_to_guest', 'tcp_synack_from_guest', 'tcp_rst_from_guest', 'udp_replies_from_guest',
                                       'icmp_echo_reply_from_guest', 'guest_broadcast_udp')})
        # The guest's own record of who reached the listener must equal what the observer achieved.
        heard = rows(work / 'listener.jsonl')
        expected_tcp = sum(1 for label in ('permitted', 'admin-disabled', 'service-stopped') if (observation(label) or {}).get('listener_tcp_reachable'))
        gate('guest_listener_log_matches_observer', expected_tcp > 0 and sum(row.get('listener') == 'tcp' for row in heard) == expected_tcp and
             all(row.get('peer') == '10.25.0.1' for row in heard if row.get('listener') == 'tcp'),
             {'tcp_connections_logged': sum(row.get('listener') == 'tcp' for row in heard), 'expected': expected_tcp,
              'udp_datagrams_logged': sum(row.get('listener') == 'udp' for row in heard)})
        # The guest-side record: after the quiet period the listener received nothing from either peer.
        if expiry.get('kind') == 'udp-expiry':
            late = [row for row in heard if row.get('listener') == 'udp' and row.get('peer') == '10.25.0.3']
            gate('guest_listener_received_nothing_after_expiry', not late, {'datagrams_from_new_peer': len(late)})
        waits = {name: marker(name) for name in re.findall(r'^(XP25_HOST_WAIT_\w+)=', serial, re.M)}
        broadcasts = capture.get('whole_capture', {}).get('guest_broadcast_udp', {}).get(port, 0)
        gate('listener_broadcast_rate_bounded', 0 < broadcasts < 6 * 3600, {'listener_broadcasts_in_capture': broadcasts})
        gate('every_observation_completed', len(waits) >= 12 and all(v and set(v) == {0} for v in waits.values()), {k: v for k, v in waits.items() if set(v) != {0}})
    def cases(path, context_prefix):
        """Probe records of one context: from the result file on the frozen disk, else the relayed serial copy."""
        found = rows(path) if path.is_file() else []
        if not found:
            found = [json.loads(line[line.index('{'):]) for line in lines if '"security_case"' in line and
                     ('"context":"%s' % context_prefix) in line]
        return [row for row in found if 'security_case' in row]

    def all_passed(name, found, minimum, crashes=None):
        """Every case passed. Crash-on-close cases are judged separately when crashes is given: only a crash
        the unhardened base shows too (KNOWN_CRASHES, run apps-base-up-01) is not a regression."""
        crash_cases = [row for row in found if row['security_case'].endswith('_closes_without_crashing')]
        rest = [row for row in found if row not in crash_cases] if crashes is not None else found
        failed = [(row['security_case'], row.get('note', '')[:90]) for row in rest if row.get('status') == 'fail']
        skipped = [row['security_case'] for row in rest if row.get('status') == 'not_run']
        gate(name, len([row for row in rest if row.get('status') == 'pass']) >= minimum and not failed and not skipped,
             {'passed': sum(row.get('status') == 'pass' for row in rest), 'failed': failed[:8], 'not_run': skipped})
        if crashes is not None:
            seen = sorted(row['security_case'] for row in crash_cases if row.get('status') == 'fail')
            gate(crashes, set(seen) <= KNOWN_CRASHES, {'crashed_on_close': seen, 'also_on_the_unhardened_base': sorted(KNOWN_CRASHES)})

    if role in ('proof', 'apps'):
        all_passed('legacy_programs_and_games_start_and_respond', cases(work / ('apps-%s.jsonl' % ('proof' if role == 'proof' else 'admin')), 'apps_'), 14,
                   'no_program_crash_beyond_the_unhardened_base')
    if role == 'ai-repeat':
        rounds = inputs.get('repeat') or 1
        ai = re.findall(r'AI_PROBE_COMPLETE passes=(\d+) failures=(\d+)', serial)
        suites, providers = ai[0::2], ai[1::2]
        gate('every_round_completed', serial.count('XP25_AI_ROUND_DONE=') == rounds and len(ai) == 2 * rounds, {'rounds': rounds, 'completed': len(ai)})
        gate('clippyai_and_roverai_ended_before_every_round', marker('XP25_AI_RESET_EXIT') == [0] * rounds, marker('XP25_AI_RESET_EXIT'))
        for n in range(rounds):
            gate('round_%d_ai_suite_55_cases' % (n + 1), n < len(suites) and suites[n] == ('55', '0'), suites[n] if n < len(suites) else None)
            gate('round_%d_ai_provider_7_cases' % (n + 1), n < len(providers) and providers[n] == ('7', '0'), providers[n] if n < len(providers) else None)
        failed = [line.strip()[:160] for line in lines if '"ai_case"' in line and '"status":"fail"' in line]
        gate('no_failed_ai_case', not failed, failed[:6])
        timings = {}
        for line in lines:
            if '"ai_timing"' in line:
                row = json.loads(line[line.index('{'):])
                timings.setdefault(row['ai_timing'], []).append(row['ms'])
        (run / 'ai-timings.json').write_text(json.dumps(timings, indent=1) + '\n')
        gate('timings_recorded', bool(timings.get('clippy_minimize_processed')) and bool(timings.get('settings_ok_processed')),
             {name: {'n': len(v), 'max_ms': max(v), 'median_ms': sorted(v)[len(v) // 2]} for name, v in timings.items()})
    if role == 'standard-user':
        whoami = (work / 'std-whoami-1.txt').read_text('latin-1', 'replace').strip().lower() if (work / 'std-whoami-1.txt').is_file() else ''
        admins = (work / 'std-groups-admins.txt').read_text('latin-1', 'replace').lower() if (work / 'std-groups-admins.txt').is_file() else ''
        users = (work / 'std-groups-users.txt').read_text('latin-1', 'replace').lower() if (work / 'std-groups-users.txt').is_file() else ''
        gate('standard_account_created_as_user_only', marker('XP25_STD_ACCOUNT_CREATED') == [0] and 'xp25user' in users and 'xp25user' not in admins,
             {'created': marker('XP25_STD_ACCOUNT_CREATED'), 'in_users': 'xp25user' in users, 'in_administrators': 'xp25user' in admins})
        typed = [json.loads(line).get('logon_typed_for') for line in (run / 'journal.jsonl').read_text().splitlines() if 'logon_typed_for' in line]
        whoami2 = (work / 'std-whoami-2.txt').read_text('latin-1', 'replace').strip().lower() if (work / 'std-whoami-2.txt').is_file() else ''
        gate('logons_in_planned_order', [u for i, u in enumerate(typed) if i == 0 or typed[i - 1] != u] == ['xp25', 'xp25user'] and
             whoami.endswith('\\xp25user') and whoami2.endswith('\\xp25user') and marker('XP25_STD_NEXT_ACCOUNT_OFFERED') == [0],
             {'typed': typed, 'whoami': [whoami, whoami2]})
        all_passed('standard_user_desktop_first_logon', cases(work / 'std-desktop-1.jsonl', 'desktop_'), 25)
        all_passed('standard_user_programs_and_games', cases(work / 'std-apps-1.jsonl', 'apps_'), 14, 'standard_user_no_program_crash_beyond_the_unhardened_base')
        all_passed('standard_user_desktop_after_restart', cases(work / 'std-desktop-2.jsonl', 'desktop_'), 25)
        gate('standard_user_restarted_the_computer', 'XP25_STD_USER_RESTART' in serial and serial.count('{"xp25_winlogon":"core_ready"') == 3 and
             serial.index('XP25_STD_USER_RESTART') < serial.rindex('{"xp25_winlogon":"core_ready"') and 'XP25_STD_RESTART_REQUEST_EXIT' not in serial)
        # COM1 markers written at the very start of a session can lose the port to the logon process;
        # the second session is shown by its results file and its exit marker instead.
        second = bool(rows(work / 'std-desktop-2.jsonl')) and bool(marker('XP25_STD_DESKTOP_EXIT_2'))
        gate('standard_user_powered_the_computer_off', second and 'XP25_SEC_SUITE_DONE' in serial and
             serial.index('XP25_STD_DESKTOP_EXIT_2') < serial.index('XP25_SEC_SUITE_DONE') and
             'XP25_STD_SHUTDOWN_REQUEST_EXIT' not in serial and event.get('data') == {'guest': True, 'reason': 'guest-shutdown'})
    if role in ('audit', 'harden', 'proof', 'rollback'):
        label = {'audit': 'before', 'harden': 'hardened', 'proof': 'proof', 'rollback': 'rolled-back'}[role]
        scan = json.loads((run / ('scan-result-%s.json' % label)).read_text()) if (run / ('scan-result-%s.json' % label)).is_file() else None
        check = json.loads((run / ('scan-check-%s.json' % label)).read_text()) if (run / ('scan-check-%s.json' % label)).is_file() else {}
        if scan is None:
            gate('external_scan_performed', False)
        else:
            answered = sorted(port for port, state in scan['udp'].items() if state['state'] == 'response')
            burst, listener = scan.get('udp_137_burst'), scan.get('listener_burst')
            detail = {'tcp_open': scan['tcp_open'], 'tcp_filtered': scan['tcp_filtered_count'], 'tcp_closed': scan['tcp_closed_count'],
                      'udp_answered': answered, 'udp_137_burst': burst, 'listener_burst': listener, 'listener_tcp': scan.get('listener_tcp'),
                      'icmp_echo_reply': scan['icmp_echo_reply'],
                      'inside_scan_window': check.get('inside_window')}
            if role == 'audit':
                gate('external_scan_recorded', True, detail)
            elif role == 'rollback':
                # Rollback restores the original firewall settings, so the broadcast-response window is open
                # again exactly as before hardening: the name service answers while the guest broadcasts.
                # Unsolicited TCP stays filtered, because the kernel export that lets the firewall run is
                # not part of the tool's rollback.
                gate('original_firewall_behaviour_restored', burst is not None and listener is not None and
                     (burst['answers'] > 0 or listener['answers'] > 0) and not scan['tcp_open'], detail)
            else:
                # The name-service burst runs while the guest itself broadcasts from UDP 137; a scan without it proves less.
                gate('nothing_reachable_from_the_network', not scan['tcp_open'] and not answered and not scan['icmp_echo_reply'] and
                     scan['tcp_filtered_count'] == scan['tcp_ports_probed'] and burst is not None and burst['answers'] == 0 and
                     listener is not None and listener['answers'] == 0 and scan.get('listener_tcp') == 'filtered', detail)
            if check:
                gate('scan_ran_while_guest_was_up', check.get('inside_window') is True, check)
            wire = capture['segments'].get(label)
            port = str(security_fixtures.LISTENER_PORT)
            if wire is not None and role != 'audit':
                # What the wire carried during the scan: the guest broadcast name queries the whole time,
                # the observer's probes arrived, and (hardened) the guest sent nothing back to them.
                quiet = not wire['tcp_synack_from_guest'] and not wire['tcp_rst_from_guest'] and not wire['udp_replies_from_guest'] and \
                    not wire['icmp_echo_reply_from_guest']
                # The listener broadcasts from its port all the time; NetBIOS broadcasts only where it is not a point-to-point node.
                gate('capture_shows_guest_broadcasting_during_scan', wire['guest_broadcast_udp'].get(port, 0) > 10 and
                     sum(wire['tcp_syn_to_guest'].values()) >= scan['tcp_ports_probed'] and wire['udp_to_guest'].get('137', 0) >= 60 and
                     wire['udp_to_guest'].get(port, 0) >= 20,
                     {'guest_listener_broadcasts': wire['guest_broadcast_udp'].get(port, 0), 'guest_name_broadcasts': wire['guest_broadcast_udp'].get('137', 0),
                      'syn_to_guest': sum(wire['tcp_syn_to_guest'].values()), 'name_probes_to_guest': wire['udp_to_guest'].get('137', 0),
                      'listener_probes_to_guest': wire['udp_to_guest'].get(port, 0)})
                if role != 'rollback':
                    gate('capture_confirms_guest_sent_no_answer', quiet,
                         {k: wire[k] for k in ('tcp_synack_from_guest', 'tcp_rst_from_guest', 'udp_replies_from_guest', 'icmp_echo_reply_from_guest')})
    if role in ('image-install', 'image-upgrade'):
        prefix = 'install' if role == 'image-install' else 'upgrade-81'
        gate('reference_snapshot_recorded', marker('XP25_SEC_SNAPSHOT_EXIT') == [0])
        gate('test_payload_removed', marker('XP25_SEC_WORKDIR_REMOVED') == [0] and
             'error' in extracted.get('/Documents and Settings/XP25/xp25sec-security_probe.exe', {'error': 1}) and
             'error' in extracted.get('/Documents and Settings/XP25/xp25sec-suite.cmd', {'error': 1}) and
             'error' in extracted.get('/xp25sec/phase1.done', {'error': 1}))
        verify = rows(store / (prefix + '-verify.jsonl'))
        gate('install_record_kept_in_store', verify and all(row.get('ok', True) for row in verify) and rows(store / (prefix + '-apply.jsonl')) and
             (store / 'baseline-backup.txt').is_file() and (store / 'audit-snapshot.txt').is_file())
    if role == 'image-upgrade':
        # The image was verified against its own baseline first; the upgrade then changed only what the
        # new baseline adds, and recorded the original of everything it changed.
        gate('previous_baseline_intact_before_upgrade', marker('XP25_SEC_VERIFY_BEFORE_UPGRADE_EXIT') == [0])
        applied = rows(store / 'upgrade-81-apply.jsonl')
        changed = sorted(row.get('id') for row in applied if row.get('kind') == 'apply' and (row.get('result') or row.get('outcome') or '').startswith('changed') or
                         (row.get('kind') == 'apply' and row.get('item') == 'acl' and row.get('reset')))
        new_items = {'netbt.nodetype', 'acl.tasks', 'acl.firewall_service', 'acl.security_center_service', 'acl.xp25_broker_service'}
        gate('upgrade_changed_only_new_baseline_items', changed and set(changed) <= new_items, {'changed': changed})
        backup = (store / 'baseline-backup.txt').read_text('latin-1') if (store / 'baseline-backup.txt').is_file() else ''
        gate('originals_of_new_items_recorded', all((' ' + item + ' ') in backup for item in changed), {'changed': changed})
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

    if role == 'cve':
        # The login gate (xp25_winlogon_logon_each_boot, above) already proves the rebuilt lsasrv.dll
        # authenticates. These gates confirm the MS04-011 fix in that installed binary.
        probe = re.findall(r'SECURITY_PROBE_COMPLETE context=(\w+) passes=(\d+) failures=(\d+) observed=(\d+) not_run=(\d+)', serial)
        gate('security_probe_administrator', any(p[0] == 'admin' and p[2] == '0' and int(p[1]) >= 30 for p in probe) and
             marker('XP25_SEC_PROBE_EXIT') == [0], probe)
        gate('security_probe_ordinary_account', any(p[0] == 'ordinary_account' and p[2] == '0' and int(p[1]) >= 60 for p in probe), probe)
        gate('security_probe_restricted_token', any(p[0] == 'restricted_token' and p[2] == '0' and int(p[1]) >= 60 for p in probe), probe)
        cve_cases = [json.loads(line[line.index('{'):]) for line in lines
                     if '"security_case"' in line and 'ms04_011' in line]
        failed = [(c['security_case'], c['context'], c.get('note', '')[:70]) for c in cve_cases if c.get('status') == 'fail']
        # The hostile over-long DsRole name does not crash LSASS and is not granted. The privileged
        # path (admin) and the browser-containment boundary (restricted token) must both show it; the
        # ordinary-account case is the same boundary and is included when the seclogon child reports it.
        for stem in ('ms04_011_dsrole_hostile_name_no_crash_', 'ms04_011_dsrole_upgrade_not_granted_'):
            passed = {c['security_case'][len(stem):] for c in cve_cases if c['security_case'].startswith(stem) and c.get('status') == 'pass'}
            gate('cve_' + stem.rstrip('_'), {'admin', 'restricted'} <= passed, sorted(passed))
        gate('ms04_011_no_failed_cve_case', not failed, failed[:6])

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
