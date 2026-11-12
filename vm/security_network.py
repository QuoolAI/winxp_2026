#!/usr/bin/env python3
"""Run one XP25 security-lab guest in the isolated namespace of
vm/isolated_network.py, optionally with the XP25 gateway and OpenAI test
double of vm/ai_network.py, plus a host-side scanner.

The scanner is the external observer for "is this port reachable from the
network": it runs in the namespace next to the guest (10.25.0.1 -> guest
10.25.0.10) and probes only that one address. A scan is requested by
creating scan-request-<label>.json in the run directory; the result appears
as scan-result-<label>.json. No uplink exists in the namespace.

Invoke under unshare --user --map-root-user --net, like isolated_network.py."""
import argparse
import concurrent.futures
import errno
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
GUEST = '10.25.0.10'
TCP_PORTS = sorted(set(range(1, 1101)) | {1433, 1723, 1900, 2869, 3306, 3389, 5000, 5001, 5357, 5800, 5900, 8080, 8443})
# Protocol-shaped requests, so a listening service answers instead of dropping garbage.
UDP_PROBES = {
    123: bytes([0x1b]) + bytes(47),                                              # SNTP client request
    137: bytes.fromhex('12340000000100000000000020434b' + '41' * 30 + '0000210001'),  # NBSTAT node status
    138: b'\x11\x02' + bytes(12),
    161: bytes.fromhex('302602010004067075626c6963a019020101020100020100300e300c06082b060102010101000500'),
    445: bytes(8),
    500: bytes.fromhex('0011223344556677' + '00' * 8 + '0110020000000000' + '0000001c'),  # ISAKMP header
    1900: b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n',
    4500: bytes(4) + bytes.fromhex('0011223344556677' + '00' * 8 + '0110020000000000' + '0000001c'),
}


def tcp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        code = s.connect_ex((GUEST, port))
    except socket.timeout:
        return port, 'filtered'
    finally:
        s.close()
    if code == 0:
        return port, 'open'
    if code == errno.ECONNREFUSED:
        return port, 'closed'
    return port, 'filtered' if code in (errno.EAGAIN, errno.ETIMEDOUT, errno.EINPROGRESS) else 'error_%d' % code


def udp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.5)
    try:
        s.connect((GUEST, port))
        for _ in range(2):                           # the first datagram can be lost to ARP resolution
            s.send(UDP_PROBES[port])
            try:
                data = s.recv(2048)
                return port, {'state': 'response', 'bytes': len(data)}
            except socket.timeout:
                continue
            except ConnectionRefusedError:
                return port, {'state': 'closed_icmp_unreachable'}
        return port, {'state': 'no_response'}        # open without an answer, or silently filtered
    finally:
        s.close()


def nbns_burst(probes=60, interval=0.5):
    """Repeated NetBIOS name-service probes. Windows Firewall admits unicast packets to a port for three
    seconds after the guest itself broadcasts from it, so one probe can miss what a neighbour can reach."""
    answers = 0
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(interval)
    try:
        s.connect((GUEST, 137))
        for _ in range(probes):
            sent = time.time()
            try:
                s.send(UDP_PROBES[137])
                s.recv(2048)
                answers += 1
                time.sleep(max(0.0, interval - (time.time() - sent)))
            except socket.timeout:
                pass
            except OSError:
                time.sleep(interval)
    finally:
        s.close()
    return {'probes': probes, 'answers': answers, 'seconds': round(probes * interval, 1)}


def scan(label):
    started = time.time()
    burst = nbns_burst()                             # first, while the guest's broadcast loop is certainly running
    ping = subprocess.run(['ping', '-c', '2', '-W', '2', GUEST], capture_output=True, text=True)
    with concurrent.futures.ThreadPoolExecutor(64) as pool:
        states = dict(pool.map(tcp, TCP_PORTS))
    datagrams = dict(udp(port) for port in sorted(UDP_PROBES))
    summary = {state: sorted(p for p, s in states.items() if s == state) for state in sorted(set(states.values()))}
    return {'label': label, 'target': GUEST, 'observer': '10.25.0.1 inside the isolated namespace (host side)',
            'started': started, 'seconds': round(time.time() - started, 2),
            'icmp_echo_reply': ping.returncode == 0,
            'tcp_ports_probed': len(TCP_PORTS), 'tcp_open': summary.get('open', []),
            'tcp_closed_count': len(summary.get('closed', [])), 'tcp_filtered_count': len(summary.get('filtered', [])),
            'tcp_other': {k: v for k, v in summary.items() if k not in ('open', 'closed', 'filtered')},
            'udp': {str(k): v for k, v in datagrams.items()}, 'udp_137_burst': burst}


def scanner(stop):
    while not stop.is_set():
        for request in sorted(Path('.').glob('scan-request-*.json')):
            label = request.stem[len('scan-request-'):]
            result = Path('scan-result-%s.json' % label)
            if result.exists():
                continue
            try:
                data = scan(label)
            except OSError as error:
                data = {'label': label, 'error': str(error)}
            Path(str(result) + '.tmp').write_text(json.dumps(data, indent=1) + '\n')
            os.replace(str(result) + '.tmp', result)
        stop.wait(0.5)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', type=Path)
    parser.add_argument('--parent-netns', required=True)
    parser.add_argument('--gateway-clients', type=Path)
    parser.add_argument('--mock-key')
    args = parser.parse_args()
    if os.readlink('/proc/self/ns/net') == args.parent_netns:
        parser.error('a fresh isolated network namespace is required')
    stop = threading.Event()
    threading.Thread(target=scanner, args=(stop,), daemon=True).start()
    try:
        if args.gateway_clients:
            sys.argv = [str(HERE / 'ai_network.py'), str(args.command), '--parent-netns', args.parent_netns,
                        '--gateway-clients', str(args.gateway_clients), '--mock-key', args.mock_key]
            sys.path.insert(0, str(HERE))
            import ai_network
            ai_network.main()
        else:
            sys.argv = [str(HERE / 'isolated_network.py'), str(args.command), '--parent-netns', args.parent_netns]
            sys.path.insert(0, str(HERE))
            import isolated_network
            isolated_network.main()
    finally:
        stop.set()


if __name__ == '__main__':
    main()
