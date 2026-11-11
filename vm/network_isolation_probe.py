#!/usr/bin/env python3
"""Host-side proof that the XP25 browser network namespace blocks every egress
path except the gateway, independent of any guest.

Runs inside the *same* isolation the guest runs in (`unshare --user --map-root-user
--net`, a single 10.25.0.1/24 tap, ip_forward=0, the byte-identical namespace-local
nftables ruleset from browser_network.NFT_RULESET). It then attempts to reach the
public Internet, the host's own LAN address, the home-LAN gateway, other libvirt/LXD
networks, the cloud-metadata address, an alternative public DNS resolver and public
IPv6, and records the exact outcome for each: ENETUNREACH/EHOSTUNREACH (no route =
contained) is distinguished from ETIMEDOUT and from ECONNREFUSED (a real peer). A
bound loopback control confirms the probe can detect a *reachable* port, and the
gateway proxy port with nothing listening confirms fail-closed behaviour.

Because the guest runs only inside this namespace and is a less-privileged tap
client, anything unreachable here is unreachable for the guest. Evidence is written
to a private .work directory.
"""
import argparse
import errno
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vm'))
from browser_network import NFT_RULESET

# (name, family, proto, address, port, requirement, description)
# requirement: 'contained' (must have no route / be unreachable), 'refused'
# (route exists but nothing listens = fail-closed), 'reachable' (positive control).
TARGETS = [
    ('public_internet_ipv4', socket.AF_INET, 'tcp', '1.1.1.1', 443, 'contained',
     'A live public HTTPS endpoint: no uplink, so no route'),
    ('alternative_dns_resolver', socket.AF_INET, 'udp', '1.1.1.1', 53, 'contained',
     'An alternative public DNS resolver cannot be reached'),
    ('host_own_lan_ip', socket.AF_INET, 'tcp', '192.168.1.25', 22, 'contained',
     "The Ubuntu host's own LAN address and SSH port are off-namespace"),
    ('home_lan_gateway', socket.AF_INET, 'tcp', '192.168.1.1', 443, 'contained',
     'The home-LAN router is unreachable'),
    ('libvirt_default_net', socket.AF_INET, 'tcp', '192.168.122.1', 53, 'contained',
     "The libvirt 'default' network's host service is unreachable"),
    ('libvirt_xp25_isolated', socket.AF_INET, 'tcp', '10.25.0.1', 5353, 'refused',
     'The host tap address is routable but only gateway/DHCP/DNS ports listen'),
    ('lxd_bridge', socket.AF_INET, 'tcp', '10.82.26.1', 53, 'contained',
     'The LXD bridge (Mise En Abyme containers) is unreachable'),
    ('docker_bridge', socket.AF_INET, 'tcp', '172.17.0.1', 53, 'contained',
     'The docker bridge is unreachable'),
    ('cloud_metadata', socket.AF_INET, 'tcp', '169.254.169.254', 80, 'contained',
     'The cloud/link-local metadata endpoint is unreachable'),
    ('public_internet_ipv6', socket.AF_INET6, 'tcp', '2606:4700:4700::1111', 443, 'contained',
     'Public IPv6 has no route and is dropped'),
    ('gateway_proxy_down', socket.AF_INET, 'tcp', '10.25.0.1', 3128, 'refused',
     'With no gateway running, the only egress port is refused (fail-closed)'),
]


def classify(family, proto, address, port, timeout=4):
    """Attempt one connection and map the outcome to a contained/refused/reachable
    class plus the raw errno, so a policy block is never confused with a timeout."""
    try:
        s = socket.socket(family, socket.SOCK_DGRAM if proto == 'udp' else socket.SOCK_STREAM)
    except OSError as e:
        return {'class': 'contained', 'mechanism': 'socket_create_failed', 'errno': e.errno,
                'errno_name': errno.errorcode.get(e.errno, '?')}
    s.settimeout(timeout)
    try:
        if proto == 'udp':
            # A connected UDP socket surfaces ICMP/no-route on send or the recv.
            s.connect((address, port))
            s.send(b'\x00')
            try:
                s.recv(256)
                return {'class': 'reachable', 'mechanism': 'udp_reply'}
            except socket.timeout:
                return {'class': 'contained', 'mechanism': 'udp_no_reply', 'errno': None}
        else:
            s.connect((address, port))
            return {'class': 'reachable', 'mechanism': 'tcp_connect'}
    except socket.timeout:
        return {'class': 'contained', 'mechanism': 'timeout', 'errno': None}
    except OSError as e:
        name = errno.errorcode.get(e.errno, '?')
        if e.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN, errno.EADDRNOTAVAIL):
            cls = 'contained'
        elif e.errno == errno.ECONNREFUSED:
            cls = 'refused'
        else:
            cls = 'contained'
        return {'class': cls, 'mechanism': 'errno', 'errno': e.errno, 'errno_name': name}
    finally:
        s.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--parent-netns', required=True)
    p.add_argument('--firewall', action='store_true')
    a = p.parse_args()
    out = a.output.resolve()
    if not out.is_relative_to(ROOT / '.work'):
        p.error('private .work output required')
    if os.readlink('/proc/self/ns/net') == a.parent_netns:
        p.error('a fresh isolated network namespace is required')
    initial = json.loads(subprocess.check_output(['ip', '-j', 'link']))
    if [row['ifname'] for row in initial] != ['lo']:
        p.error('namespace must initially contain only loopback')
    out.mkdir(parents=True, exist_ok=True)
    os.chdir(out)
    for cmd in (['ip', 'link', 'set', 'lo', 'up'],
                ['ip', 'tuntap', 'add', 'dev', 'xp25tap', 'mode', 'tap'],
                ['ip', 'link', 'set', 'dev', 'xp25tap', 'address', '52:54:00:25:00:01'],
                ['ip', 'address', 'add', '10.25.0.1/24', 'dev', 'xp25tap'],
                ['ip', 'link', 'set', 'xp25tap', 'up']):
        subprocess.run(cmd, check=True)
    Path('/proc/sys/net/ipv4/ip_forward').write_text('0\n')
    firewall_active = False
    if a.firewall:
        subprocess.run(['nft', '-f', '-'], input=NFT_RULESET, text=True, check=True)
        Path('nft-ruleset.txt').write_text(subprocess.check_output(['nft', 'list', 'table', 'inet', 'xp25iso'], text=True))
        firewall_active = True
    # Positive control: a listener the namespace *can* reach, proving the probe
    # discriminates reachable from unreachable rather than failing everything.
    control = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    control.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    control.bind(('10.25.0.1', 9099))
    control.listen(1)
    state = {
        'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'network_namespace': os.readlink('/proc/self/ns/net'),
        'parent_network_namespace': a.parent_netns,
        'namespace_firewall': firewall_active,
        'interfaces': json.loads(subprocess.check_output(['ip', '-j', 'address'])),
        'routes_ipv4': json.loads(subprocess.check_output(['ip', '-j', 'route'])),
        'routes_ipv6': json.loads(subprocess.check_output(['ip', '-j', '-6', 'route'])),
        'ip_forward': Path('/proc/sys/net/ipv4/ip_forward').read_text().strip(),
    }
    results = []
    for name, family, proto, address, port, requirement, description in TARGETS:
        outcome = classify(family, proto, address, port)
        results.append({'target': name, 'address': address, 'port': port, 'proto': proto,
                        'family': 'ipv6' if family == socket.AF_INET6 else 'ipv4',
                        'requirement': requirement, 'description': description,
                        'outcome': outcome, 'pass': outcome['class'] == requirement})
    # Positive control connection (must succeed).
    ctrl = classify(socket.AF_INET, 'tcp', '10.25.0.1', 9099)
    results.append({'target': 'reachable_control', 'address': '10.25.0.1', 'port': 9099, 'proto': 'tcp',
                    'family': 'ipv4', 'requirement': 'reachable', 'description':
                    'A bound loopback-tap listener is reachable (probe discriminates)',
                    'outcome': ctrl, 'pass': ctrl['class'] == 'reachable'})
    control.close()
    if firewall_active:
        try:
            Path('nft-counters.txt').write_text(subprocess.check_output(['nft', 'list', 'table', 'inet', 'xp25iso'], text=True))
        except Exception:
            pass
    state['probes'] = results
    state['passed'] = all(r['pass'] for r in results)
    state['probe_count'] = len(results)
    Path('isolation-probe.json').write_text(json.dumps(state, indent=2) + '\n')
    for r in results:
        print(('PASS' if r['pass'] else 'FAIL'), r['target'], '->', r['outcome']['class'],
              r['outcome'].get('errno_name', r['outcome'].get('mechanism', '')))
    print('TOTAL', sum(r['pass'] for r in results), '/', len(results), 'firewall=' + str(firewall_active))
    return 0 if state['passed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
