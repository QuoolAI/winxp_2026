#!/usr/bin/env python3
"""Check the latest serial probe groups and independent host network records.

Authentication transitions and Notepad evidence require separate review.
"""
import argparse
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    directory = parser.parse_args().directory.resolve()
    raw = (directory / 'serial.log').read_bytes()
    observations = []
    for line in raw.decode(errors='replace').splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            observations.append(item)
    groups = {
        'standard': ('name', 'guest_identity', ['guest_identity', 'explorer_presence',
                     'registry', 'filesystem', 'winsock_loopback', 'driver_enumeration']),
        'pointer': ('case', 'exports_resolved', ['exports_resolved',
                    'null_allones_function_roundtrip_nonidentity',
                    'concurrent_262144_roundtrips_stable_cookie', 'self_cookie_query_length',
                    'real_handle_query_rejected', 'bad_length_rejected', 'bad_output_buffer_rejected',
                    'bad_return_length_buffer_rejected', 'other_process_cookie_query_rejected',
                    'distinct_process_encoding', 'pointer_probe_complete']),
        'session': ('case', 'account_name', ['account_name', 'user_primary_logon_token',
                    'explorer_same_user_and_logon_session', 'visible_window_station',
                    'default_interactive_desktop', 'session_probe_complete']),
        'network': ('case', 'winsock_startup', ['winsock_startup', 'ipv4_address_port_parsing',
                    'ipv4_invalid_octet_rejected', 'tcp_loopback', 'udp_loopback',
                    'virtual_nic_controlled_ipv4', 'controlled_dhcp_lease',
                    'controlled_dns_resolution', 'isolated_server_tcp_connection', 'isolated_http_response',
                    'service_Afd_running', 'service_Tcpip_running', 'service_Dhcp_running',
                    'service_Dnscache_running', 'service_PlugPlay_running', 'service_RpcSs_running',
                    'network_probe_complete'])}
    result = {}
    for group, (field, start, names) in groups.items():
        starts = [i for i, row in enumerate(observations) if row.get(field) == start]
        rows = {row[field]: row for row in observations[starts[-1]:] if row.get(field) in names} if starts else {}
        result[group] = {'passed': len(rows) == len(names) and all(row.get('status') == 'pass' for row in rows.values()),
                         'observations': rows}
    dns = (directory / 'dnsmasq.log').read_text()
    http = [json.loads(line) for line in (directory / 'http.jsonl').read_text().splitlines()]
    isolation = json.loads((directory / 'network-isolation.json').read_text())
    shutdown = json.loads((directory / 'normal-shutdown.json').read_text())
    result['host_corroboration'] = {
        'dhcp_ack': 'DHCPACK(xp25tap) 10.25.0.10 52:54:00:25:00:02' in dns,
        'dns_answer': 'query[A] xp25.test from 10.25.0.10' in dns and 'config xp25.test is 10.25.0.1' in dns,
        'http_requests': sum(row['client'][0] == '10.25.0.10' and
                             'GET /xp25-network-proof HTTP/1.0" 200' in row['message'] for row in http),
        'isolated': isolation['ip_forward'] == '0' and
                    isolation['network_namespace'] != isolation['parent_network_namespace'] and
                    {x['ifname'] for x in isolation['interfaces']} == {'lo', 'xp25tap'} and
                    all(x['dst'] == '10.25.0.0/24' for x in isolation['routes']),
        'guest_shutdown_before_quit': shutdown['qemu_status']['status'] == 'shutdown' and shutdown['quit_after_shutdown']}
    result['completed_network_runs'] = sum(row.get('case') == 'network_probe_complete' and
                                           row.get('status') == 'pass' for row in observations)
    result['historical_failed_observations'] = [row for row in observations if row.get('status') == 'fail']
    result['serial_sha256'] = hashlib.sha256(raw).hexdigest()
    result['disk_sha256'] = json.loads((directory / 'checkpoint.json').read_text())['disk_sha256']
    result['automated_gates_passed'] = all(result[x]['passed'] for x in groups) and all(result['host_corroboration'].values())
    (directory / 'network-results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'experiment': directory.name, 'automated_gates_passed': result['automated_gates_passed'],
                      'completed_network_runs': result['completed_network_runs'],
                      'http_requests': result['host_corroboration']['http_requests']}))
    return 0 if result['automated_gates_passed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
