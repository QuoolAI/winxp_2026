#!/usr/bin/env python3
"""Validate original Regsvc/GINA/UserEnv experiments without promoting stale evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build'))
from inspect_component import PE

REGSVC = ('remote_registry_service_access', 'service_initial_stop', 'rpc_stopped_service_rejected',
          'bounded_rpc_worker_exit', 'service_start', 'service_module_mapped', 'rpc_connect_loopback',
          'rpc_read_os_identity', 'rpc_matches_local_registry', 'rpc_fixture_name_unused',
          'rpc_create_own_key', 'rpc_write_own_value', 'rpc_read_own_value', 'rpc_write_visible_locally',
          'rpc_delete_own_value', 'rpc_delete_own_key', 'rpc_worker_complete', 'service_stop',
          'service_restart', 'original_service_running_state_restored', 'regsvc_probe_complete')
GINA = ('interactive_session_winlogon_found', 'msgina_mapped_in_real_winlogon',
        'user_cannot_write_secure_desktop', 'gina_probe_complete')
USERENV = ('load_userenv', 'all_49_named_sp3_ordinals_match', 'original_59_private_exports_present',
           'profile_token_and_api_access', 'profile_unicode_buffer_contract', 'profile_matches_logged_on_user',
           'profile_ansi_unicode_agree', 'all_users_profile_path', 'default_user_profile_path',
           'create_user_environment', 'environment_userprofile_matches', 'destroy_user_environment',
           'expand_environment_for_user', 'userenv_probe_complete')
SHELL = ('desktop_and_taskbar_present', 'live_explorer_image_read', 'start_menu_opens', 'luna_theme_active',
         'fixture_directory_unused', 'fixture_directory_created', 'fixture_file_created', 'open_folder_request',
         'folder_window_and_list_view', 'folder_displays_fixture', 'fixture_file_removed',
         'fixture_directory_removed', 'taskbar_survives_navigation', 'shell_probe_complete')
PROFILE = ('profile_api_access', 'existing_profile_privileges_enabled', 'fixture_account_unused',
           'fixture_account_created', 'fixture_authentication', 'fixture_token_sid', 'new_profile_initialized',
           'new_profile_path', 'new_profile_hive_mounted', 'new_profile_registry_roundtrip',
           'new_profile_unloaded', 'new_profile_deleted', 'fixture_account_deleted', 'profile_probe_complete')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def group(text, start_marker, exit_marker):
    start = text.rfind(start_marker)
    end = text.find(exit_marker, start) if start >= 0 else -1
    rows = []
    for line in text[start:end].splitlines() if end >= 0 else []:
        try:
            rows.append(json.loads(line))
        except ValueError:
            pass
    return rows, end >= 0 and text[end:].splitlines()[0].strip() == exit_marker + '0'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory', type=Path)
    p.add_argument('--expected-regsvc', type=Path, required=True)
    p.add_argument('--expected-gina', type=Path)
    p.add_argument('--baseline', type=Path, required=True)
    p.add_argument('--notepad-marker')
    p.add_argument('--userenv-package', type=Path)
    p.add_argument('--userenv-control', action='store_true')
    p.add_argument('--expected-explorer', type=Path, help='require live shell identity and functional shell/profile tests')
    args = p.parse_args()
    directory, baseline = args.directory.resolve(), args.baseline.resolve()
    if any(not x.is_relative_to(ROOT / '.work') for x in (directory, baseline, args.expected_regsvc.resolve())):
        p.error('private experiment and binary paths required')
    result_path = directory / 'extension-results.json'
    if result_path.exists():
        previous = result_path.read_bytes()
        (directory / ('extension-results.previous-' + hashlib.sha256(previous).hexdigest()[:12] + '.json')).write_bytes(previous)
        result_path.unlink()
    core = json.loads((directory / 'component-results.json').read_text())
    text = (directory / 'serial.log').read_text(errors='replace')
    records, exit_ok = group(text, 'REGSVC_PROBE_STARTED', 'REGSVC_PROBE_EXIT=')
    rows = {r['regsvc_case']: r for r in records if r.get('regsvc_case') in REGSVC}
    identities = [r for r in records if r.get('regsvc_image_identity')]
    expected = PE(args.expected_regsvc).inspect()
    checks = {
        'core_regression_gates_and_evidence_fresh': core['passed'] and all(sha(directory / n) == h for n, h in core['evidence_sha256'].items()),
        'regsvc_cases_complete': set(rows) == set(REGSVC) and all(r['status'] == 'pass' for r in rows.values()),
        'regsvc_exit_zero': exit_ok,
        'two_complete_rpc_roundtrips': sum(r.get('regsvc_case') == 'rpc_worker_complete' and r.get('status') == 'pass' for r in records) == 2,
        'two_stopped_server_rejections': sum(r.get('regsvc_case') == 'rpc_stopped_service_rejected' and r.get('status') == 'pass' for r in records) == 2,
        'four_bounded_worker_exits': sum(r.get('regsvc_case') == 'bounded_rpc_worker_exit' and r.get('status') == 'pass' for r in records) == 4,
        'actual_regsvc_loaded_checksum': len(identities) == 1 and identities[0].get('read') == 1 and identities[0]['pe_checksum'] == int(expected['checksum_stored'], 16),
        'regsvc_file_retained': sha(directory / 'retention/WINDOWS/system32/regsvc.dll') == expected['sha256'],
        'captured_identity_unchanged': (directory / 'retention/xp25/branding-identity.bin').read_bytes() == (baseline / 'retention/xp25/branding-identity.bin').read_bytes(),
        'fresh_service_shutdown_proof': text.rfind('SHUTDOWN_PROOF_CLEARED') > text.rfind('SERVICE_PROBE_EXIT=') >= 0,
        'all_installer_fixture_steps_zero': all([l.strip() for l in text.splitlines() if l.startswith(name + '=')][-1:] == [name + '=0'] for name in
            ('MSI_BUILD_EXIT', 'MSI_INSTALL_EXIT', 'MSI_INSTALLED_STATE_EXIT', 'MSI_UNINSTALL_EXIT', 'MSI_UNINSTALLED_STATE_EXIT')),
    }
    gina_rows = []
    if args.expected_gina:
        gina_rows, gina_exit = group(text, 'GINA_PROBE_STARTED', 'GINA_PROBE_EXIT=')
        cases = {r['gina_case']: r for r in gina_rows if r.get('gina_case') in GINA}
        mapped = [r for r in gina_rows if r.get('gina_image_identity')]
        expected_gina = PE(args.expected_gina).inspect()
        checks.update(gina_cases_complete=set(cases) == set(GINA) and all(r['status'] == 'pass' for r in cases.values()),
            gina_exit_zero=gina_exit,
            actual_winlogon_gina_checksum=len(mapped) == 1 and mapped[0].get('read') == 1 and mapped[0]['pe_checksum'] == int(expected_gina['checksum_stored'], 16),
            gina_file_retained=sha(directory / 'retention/WINDOWS/system32/msgina.dll') == expected_gina['sha256'])
    if args.notepad_marker:
        checks['unique_notepad_readback'] = (directory / 'retention/xp25/component-notepad.txt').read_bytes() == args.notepad_marker.encode('ascii')
    if args.userenv_package or args.userenv_control:
        records_ue, ue_exit = group(text, 'USERENV_PROBE_STARTED', 'USERENV_PROBE_EXIT=')
        names = set(USERENV) | ({'three_exact_original_sp3_forward_targets'} if args.userenv_package else set())
        ue = {r['userenv_case']: r for r in records_ue if r.get('userenv_case') in names}
        checks['userenv_profile_and_abi_cases'] = set(ue) == names and all(r['status'] == 'pass' for r in ue.values())
        checks['userenv_exit_zero'] = ue_exit
        if args.userenv_package:
            package = args.userenv_package.resolve()
            if not package.is_relative_to(ROOT / '.work'):
                p.error('private UserEnv package required')
            manifest = json.loads((package / 'manifest.json').read_text())
            checks['source_userenv_and_original_sp3_dependency_retained'] = all(
                sha(directory / 'retention/WINDOWS/system32' / name) == digest for name,digest in manifest['components'].items())
            checks['original_userenv_recovery_retained'] = sha(directory / 'retention/xp25/recovery-userenv.dll') == manifest['original_sp3_sha256']
    if args.expected_explorer:
        shell, shell_exit = group(text, 'SHELL_PROBE_STARTED', 'SHELL_PROBE_EXIT=')
        profile, profile_exit = group(text, 'PROFILE_PROBE_STARTED', 'PROFILE_PROBE_EXIT=')
        cases = {r['shell_case']:r for r in shell if r.get('shell_case') in SHELL}
        profiles = {r['profile_case']:r for r in profile if r.get('profile_case') in PROFILE}
        actual = [r for r in shell if r.get('shell_image_identity')]
        explorer = PE(args.expected_explorer).inspect()
        userenv = PE(directory / 'retention/WINDOWS/system32/userenv.dll').inspect()
        mapped = [r for r in gina_rows if r.get('winlogon_userenv_identity')]
        checks.update(shell_functional_cases=set(cases)==set(SHELL) and all(r['status']=='pass' for r in cases.values()),
            shell_exit_zero=shell_exit, fresh_profile_cases=set(profiles)==set(PROFILE) and all(r['status']=='pass' for r in profiles.values()),
            profile_exit_zero=profile_exit,
            actual_explorer_loaded=len(actual)==1 and actual[0]['read']==1 and actual[0]['pe_checksum']==int(explorer['checksum_stored'],16),
            exact_explorer_retained=sha(directory / 'retention/WINDOWS/explorer.exe')==explorer['sha256'],
            actual_winlogon_userenv=len(mapped)==1 and mapped[0]['read']==1 and mapped[0]['pe_checksum']==int(userenv['checksum_stored'],16))
        original_explorer = baseline / 'retention/WINDOWS/explorer.exe'
        if explorer['sha256'] != sha(original_explorer):
            checks['original_explorer_recovery_retained'] = sha(directory / 'retention/xp25/recovery-explorer.exe') == sha(original_explorer)
    files = [directory / n for n in ('serial.log', 'component-results.json', 'native-stack-verification.json', 'checkpoint.json', 'normal-shutdown.json', 'inputs.json')]
    files += [f for f in (directory / 'retention').rglob('*') if f.is_file()]
    result = {'passed': all(checks.values()), 'checks': checks, 'regsvc': records, 'gina': gina_rows,
              'expected_regsvc': expected['sha256'], 'baseline': str(baseline),
              'limitations': ['Local named-pipe RPC only; SMB transport failed in the first installed-SP3 control.',
                             'GUI authentication/locking observations require separate recorded review.',
                             'No domain, cross-forest, smart-card, RDP or sustained/security certification.'],
              'evidence_sha256': {str(f.relative_to(directory)): sha(f) for f in files}}
    result_path.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'experiment': directory.name, 'passed': result['passed'], 'checks': checks}))
    return 0 if result['passed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
