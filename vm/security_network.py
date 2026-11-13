#!/usr/bin/env python3
"""Run one XP25 security-lab guest in the isolated namespace of
vm/isolated_network.py, optionally with the XP25 gateway and OpenAI test
double of vm/ai_network.py, plus a host-side scanner.

The scanner is the external observer for "is this port reachable from the
network": it runs in the namespace next to the guest (10.25.0.1 -> guest
10.25.0.10) and probes only that one address. A scan is requested by
creating scan-request-<label>.json in the run directory; the result appears
as scan-result-<label>.json. No uplink exists in the namespace.

The guest can also ask for an observation itself, so that guest steps and
host probes are ordered without timing assumptions: it writes
XP25_HOST_REQUEST=<kind>:<label> to COM1 and then polls
http://10.25.0.1:8081/done/<label> (outbound, so the guest firewall does not
interfere) until the result file exists. Kinds: scan (the full scan), ports
(the test listener, the Windows ports and a short name-service burst),
udp-series (datagrams to the listener from a known and from a new peer
address over 150 s), udp-expiry (one datagram, 150 s of silence, then one
from each peer), watch-start / watch-stop (continuous probing of every
target in between, for a restart).
Every observation is bracketed by marker frames on the tap device, which the
guest's network card does not accept but QEMU's packet capture records; the
capture is segmented by them (vm/security_pcap.py).

Invoke under unshare --user --map-root-user --net, like isolated_network.py."""
import argparse
import concurrent.futures
import errno
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
GUEST = '10.25.0.10'
HOST = '10.25.0.1'
SYNC_PORT = 8081
LISTENER_PORT = 5025                                 # tests/guest/security_probe.c "listen"
LISTENER_BANNER = b'XP25-LISTENER-OK'
TARGETED_TCP = (LISTENER_PORT, 135, 139, 445)
MARK_ETHERTYPE = b'\x88\xb5'                         # IEEE 802 local experimental 1
MARK_DESTINATION = bytes.fromhex('020000000099')     # not the guest's address: its network card drops the frame
# 5025 is the guest's own test listener during a scan: a port where something is known to listen.
TCP_PORTS = sorted(set(range(1, 1101)) | {1433, 1723, 1900, 2869, 3306, 3389, 5000, 5001, 5025, 5357, 5800, 5900, 8080, 8443})
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


def mark(text):
    """One marker frame on the tap device, for segmenting QEMU's packet capture."""
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        try:
            s.bind(('xp25tap', 0))
            s.send(MARK_DESTINATION + bytes.fromhex('525400250001') + MARK_ETHERTYPE + ('XP25-MARK:' + text).encode().ljust(46, b'\0'))
        finally:
            s.close()
        return True
    except OSError:
        return False


def tcp_banner(port, timeout=3.0):
    """Connect and read what the service says first; the test listener answers with its banner."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        code = s.connect_ex((GUEST, port))
        if code == 0:
            try:
                data = s.recv(64)
            except (socket.timeout, OSError):
                data = b''
            return {'state': 'open', 'banner': data.decode('latin-1').strip()}
        if code == errno.ECONNREFUSED:
            return {'state': 'closed'}
        if code in (errno.EHOSTUNREACH, errno.ENETUNREACH):
            return {'state': 'unreachable'}
        return {'state': 'filtered' if code in (errno.EAGAIN, errno.ETIMEDOUT, errno.EINPROGRESS) else 'error_%d' % code}
    except socket.timeout:
        return {'state': 'filtered'}
    except OSError as error:
        return {'state': 'unreachable' if error.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH) else 'error_%d' % (error.errno or 0)}
    finally:
        s.close()


def udp_echo(port, attempts=3):
    """The test listener echoes a datagram back with a prefix."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.5)
    token = b'XP25-UDP-PROBE-%d' % int(time.time() * 1000)
    try:
        s.connect((GUEST, port))
        for _ in range(attempts):
            try:
                s.send(token)
                data = s.recv(256)
                return {'state': 'response', 'echoed': token in data}
            except socket.timeout:
                continue
            except ConnectionRefusedError:
                return {'state': 'closed_icmp_unreachable'}
            except OSError as error:
                return {'state': 'error_%d' % (error.errno or 0)}
        return {'state': 'no_response'}
    finally:
        s.close()


SECOND_ADDRESS = '10.25.0.3'                         # a peer the guest has never exchanged a packet with


def second_address():
    """Adds the second observer address to the tap device (idempotent)."""
    subprocess.run(['ip', 'address', 'add', SECOND_ADDRESS + '/24', 'dev', 'xp25tap'], capture_output=True)


def udp_fresh(port, payload, source=HOST, timeout=1.0):
    """One datagram from a new socket (so a new source port) and whether anything came back."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.bind((source, 0))
        s.sendto(payload, (GUEST, port))
        s.recvfrom(2048)
        return 'response'
    except socket.timeout:
        return 'no_response'
    except ConnectionRefusedError:
        return 'closed_icmp_unreachable'
    except OSError as error:
        return 'unreachable' if error.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH) else 'error_%d' % (error.errno or 0)
    finally:
        s.close()


def icmp_echo(timeout=0.5):
    """One ICMP echo request on a raw socket; 'reply' only for an echo reply from the guest."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except OSError as error:
        return 'error_%d' % (error.errno or 0)
    try:
        ident, body = os.getpid() & 0xffff, b'XP25-ICMP-PROBE-%d' % int(time.time() * 1000)
        packet = bytes([8, 0, 0, 0, ident >> 8, ident & 255, 0, 1]) + body
        total = sum((packet[i] << 8) + (packet[i + 1] if i + 1 < len(packet) else 0) for i in range(0, len(packet), 2))
        total = (total >> 16) + (total & 0xffff)
        total = ~(total + (total >> 16)) & 0xffff
        packet = packet[:2] + bytes([total >> 8, total & 255]) + packet[4:]
        s.settimeout(timeout)
        s.sendto(packet, (GUEST, 0))
        deadline = time.time() + timeout
        while time.time() < deadline:
            data, peer = s.recvfrom(2048)
            reply = data[(data[0] & 15) * 4:]
            if peer[0] == GUEST and reply[:1] == b'\x00' and reply[8:] == body:
                return 'reply'
        return 'no_reply'
    except socket.timeout:
        return 'no_reply'
    except OSError as error:
        return 'unreachable' if error.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH) else 'error_%d' % (error.errno or 0)
    finally:
        s.close()


def udp_expiry(label, quiet=150):
    """After an exception is removed. Windows Firewall keeps state for a UDP port that has recently sent
    unicast datagrams, so a probe right after the removal may still be answered. This measures that and
    whether it ends: one datagram from the peer that used the exception, then nothing at all for `quiet`
    seconds (an answer would renew the state), then one datagram each from that peer and from an address
    the guest has never seen."""
    second_address()
    started = time.time()
    mark(label + ':start')
    immediately = udp_fresh(LISTENER_PORT, b'XP25-UDP-EXPIRY-NOW', HOST, 1.5)
    time.sleep(quiet)
    known = udp_fresh(LISTENER_PORT, b'XP25-UDP-EXPIRY-KNOWN', HOST, 1.5)
    new = udp_fresh(LISTENER_PORT, b'XP25-UDP-EXPIRY-NEW', SECOND_ADDRESS, 1.5)
    tcp_state = tcp_banner(LISTENER_PORT)
    mark(label + ':end')
    return {'label': label, 'kind': 'udp-expiry', 'target': GUEST, 'port': LISTENER_PORT, 'quiet_seconds': quiet,
            'seconds': round(time.time() - started, 1), 'immediately_after_removal': immediately,
            'after_quiet_known_peer': known, 'after_quiet_new_peer': new, 'tcp_listener': tcp_state}


def udp_series(label, seconds=150, interval=3.0):
    """After an exception is removed: datagrams to the test listener from new sockets, alternately from
    the address that used the exception before and from an address the guest has never seen, for long
    enough that any state the firewall keeps for the earlier conversation must run out or show."""
    second_address()
    started = time.time()
    mark(label + ':start')
    rows = []
    while time.time() - started < seconds:
        tick = time.time()
        token = b'XP25-UDP-SERIES-%d' % int(tick * 1000)
        rows.append({'t': round(tick - started, 1), 'known_peer': udp_fresh(LISTENER_PORT, token + b'-A', HOST),
                     'new_peer': udp_fresh(LISTENER_PORT, token + b'-B', SECOND_ADDRESS)})
        time.sleep(max(0.0, interval - (time.time() - tick)))
    tcp_state = tcp_banner(LISTENER_PORT)
    mark(label + ':end')

    def summary(key):
        answered = [row['t'] for row in rows if row[key] == 'response']
        return {'probes': len(rows), 'answered': len(answered), 'first_answer_s': answered[0] if answered else None,
                'last_answer_s': answered[-1] if answered else None}
    return {'label': label, 'kind': 'udp-series', 'target': GUEST, 'port': LISTENER_PORT, 'seconds': round(time.time() - started, 1),
            'known_peer': dict(summary('known_peer'), address=HOST), 'new_peer': dict(summary('new_peer'), address=SECOND_ADDRESS),
            'tcp_listener_afterwards': tcp_state, 'rows': rows}


def targeted(label):
    """The test listener, the Windows service ports and the name service, each probed directly."""
    started = time.time()
    marked = mark(label + ':start')
    burst = nbns_burst(20, 0.5)
    tcp_states = {str(port): tcp_banner(port) for port in TARGETED_TCP}
    echo = udp_echo(LISTENER_PORT)
    ping = subprocess.run(['ping', '-c', '2', '-W', '2', GUEST], capture_output=True, text=True)
    mark(label + ':end')
    return {'label': label, 'kind': 'ports', 'target': GUEST, 'started': started, 'seconds': round(time.time() - started, 2),
            'capture_marked': marked, 'tcp': tcp_states, 'udp_listener': echo, 'udp_137_burst': burst,
            'icmp_echo_reply': ping.returncode == 0,
            'listener_tcp_reachable': tcp_states[str(LISTENER_PORT)]['state'] == 'open' and
                                      LISTENER_BANNER.decode() in tcp_states[str(LISTENER_PORT)].get('banner', ''),
            'listener_udp_reachable': echo['state'] == 'response'}


class Watch:
    """Continuous probing between watch-start and watch-stop, e.g. across a guest restart: is there
    any moment in which the guest answers on a port the firewall is supposed to filter?"""
    def __init__(self, label):
        self.label, self.stop, self.rows, self.counts, self.ticks = label, threading.Event(), [], {}, 0
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.started = time.time()

    def observe(self, name, state):
        counts = self.counts.setdefault(name, {})
        counts[state] = counts.get(state, 0) + 1
        last = next((row for row in reversed(self.rows) if row['target'] == name), None)
        if (last is None or last['state'] != state) and len(self.rows) < 600:
            self.rows.append({'t': round(time.time() - self.started, 2), 'target': name, 'state': state})

    def run(self):
        """Every half second, all at once: the Windows TCP ports and the listener, the name service from
        one long-lived socket (a conversation that stays open once the firewall has admitted it) and
        from a new socket (a fresh attempt each time), the listener's datagram port and ICMP echo."""
        mark(self.label + ':start')
        held = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        held.setblocking(False)

        def held_name_service():
            try:
                held.sendto(UDP_PROBES[137], (GUEST, 137))
                time.sleep(0.3)
                held.recvfrom(2048)
                return 'response'
            except BlockingIOError:
                return 'no_response'
            except ConnectionRefusedError:
                return 'closed_icmp_unreachable'
            except OSError as error:
                return 'unreachable' if error.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH) else 'error_%d' % (error.errno or 0)
        probes = {'tcp/%d' % port: (lambda port=port: tcp_banner(port, 0.4)['state']) for port in (135, 139, 445, LISTENER_PORT)}
        probes['udp/137 same socket'] = held_name_service
        probes['udp/137 new socket'] = lambda: udp_fresh(137, UDP_PROBES[137], HOST, 0.4)
        probes['udp/%d new socket' % LISTENER_PORT] = lambda: udp_fresh(LISTENER_PORT, b'XP25-WATCH', HOST, 0.4)
        probes['icmp echo'] = lambda: icmp_echo(0.4)
        with concurrent.futures.ThreadPoolExecutor(len(probes)) as pool:
            while not self.stop.is_set():
                tick = time.time()
                for name, state in zip(probes, pool.map(lambda probe: probe(), probes.values())):
                    self.observe(name, state)
                neighbour = subprocess.run(['ip', '-4', 'neigh', 'show', GUEST], capture_output=True, text=True).stdout.split()
                self.observe('neighbour', neighbour[-1] if neighbour else 'none')
                self.ticks += 1
                time.sleep(max(0.0, 0.5 - (time.time() - tick)))
        held.close()
        mark(self.label + ':end')

    def result(self):
        self.stop.set()
        self.thread.join(timeout=30)
        answered = {name: {state: n for state, n in counts.items() if state in ('open', 'closed', 'response', 'closed_icmp_unreachable', 'reply')}
                    for name, counts in self.counts.items()}
        return {'label': self.label, 'kind': 'watch', 'seconds': round(time.time() - self.started, 2), 'ticks': self.ticks,
                'counts': self.counts, 'answers': {name: states for name, states in answered.items() if states}, 'transitions': self.rows,
                # The observer saw the guest's network card disappear and come back: the watch spans the restart.
                'guest_went_away': any(state in self.counts.get('neighbour', {}) for state in ('FAILED', 'INCOMPLETE', 'none'))}


def listener_burst(probes=20, interval=0.5):
    """Datagrams to the guest's broadcasting test listener, each from a new socket, while it
    broadcasts from that port every half second: answered only if replies to its broadcasts get in."""
    answers = 0
    for _ in range(probes):
        sent = time.time()
        if udp_fresh(LISTENER_PORT, b'XP25-LISTENER-BURST', HOST, interval) == 'response':
            answers += 1
        time.sleep(max(0.0, interval - (time.time() - sent)))
    return {'probes': probes, 'answers': answers, 'port': LISTENER_PORT}


def scan(label):
    started = time.time()
    mark(label + ':start')
    burst = nbns_burst()
    listener = listener_burst()                             # first, while the guest's broadcast loop is certainly running
    ping = subprocess.run(['ping', '-c', '2', '-W', '2', GUEST], capture_output=True, text=True)
    with concurrent.futures.ThreadPoolExecutor(64) as pool:
        states = dict(pool.map(tcp, TCP_PORTS))
    datagrams = dict(udp(port) for port in sorted(UDP_PROBES))
    summary = {state: sorted(p for p, s in states.items() if s == state) for state in sorted(set(states.values()))}
    mark(label + ':end')
    return {'label': label, 'kind': 'scan', 'target': GUEST, 'observer': '10.25.0.1 inside the isolated namespace (host side)',
            'started': started, 'seconds': round(time.time() - started, 2),
            'icmp_echo_reply': ping.returncode == 0,
            'tcp_ports_probed': len(TCP_PORTS), 'tcp_open': summary.get('open', []),
            'tcp_closed_count': len(summary.get('closed', [])), 'tcp_filtered_count': len(summary.get('filtered', [])),
            'tcp_other': {k: v for k, v in summary.items() if k not in ('open', 'closed', 'filtered')},
            'udp': {str(k): v for k, v in datagrams.items()}, 'udp_137_burst': burst, 'listener_burst': listener,
            'listener_tcp': states.get(LISTENER_PORT)}


def write_result(label, data):
    result = Path('scan-result-%s.json' % label)
    Path(str(result) + '.tmp').write_text(json.dumps(data, indent=1) + '\n')
    os.replace(str(result) + '.tmp', result)


def scanner(stop):
    """Serves scan-request-<label>.json files (vm/security_lab.py scan) and the guest's own
    XP25_HOST_REQUEST=<kind>:<label> lines on COM1, each label once, in order."""
    seen, watches = set(), {}
    pattern = re.compile(r'^XP25_HOST_REQUEST=([a-z-]+):([A-Za-z0-9_-]{1,40})\s*$', re.M)
    while not stop.is_set():
        requests = [('scan', request.stem[len('scan-request-'):]) for request in sorted(Path('.').glob('scan-request-*.json'))]
        try:
            text = Path('serial.log').read_bytes().decode('utf-8', 'replace').replace('\r', '')
        except OSError:
            text = ''
        requests += pattern.findall(text[:text.rfind('\n') + 1])
        for kind, label in requests:
            if (kind, label) in seen:
                continue
            seen.add((kind, label))
            try:
                if kind == 'watch-start':
                    watches[label] = Watch(label)
                    watches[label].thread.start()
                    write_result(label + '-started', {'label': label + '-started', 'kind': 'watch-start', 'started': time.time()})
                elif kind == 'watch-stop':
                    write_result(label, watches.pop(label).result() if label in watches else {'label': label, 'error': 'no such watch'})
                elif Path('scan-result-%s.json' % label).exists():
                    continue
                elif kind == 'scan':
                    write_result(label, scan(label))
                elif kind == 'ports':
                    write_result(label, targeted(label))
                elif kind == 'udp-series':
                    write_result(label, udp_series(label))
                elif kind == 'udp-expiry':
                    write_result(label, udp_expiry(label))
                else:
                    write_result(label, {'label': label, 'error': 'unknown request kind ' + kind})
            except OSError as error:
                write_result(label, {'label': label, 'error': str(error)})
        stop.wait(0.3)
    for label, watch in watches.items():
        write_result(label, dict(watch.result(), error='the run ended before watch-stop'))


class Sync(BaseHTTPRequestHandler):
    """GET /done/<label>: 200 once the observation the guest asked for is on disk."""
    def do_GET(self):
        match = re.fullmatch(r'/done/([A-Za-z0-9_-]{1,40})', self.path)
        done = bool(match) and Path('scan-result-%s.json' % match.group(1)).exists()
        body = b'XP25-HOST-DONE\n' if done else b'XP25-HOST-WAIT\n'
        self.send_response(200 if done else 404)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *values):
        pass


def sync_server(stop):
    """The tap address exists only after isolated_network.py configured the namespace; bind when it does."""
    server = None
    while not stop.is_set() and server is None:
        try:
            server = HTTPServer((HOST, SYNC_PORT), Sync)
        except OSError:
            stop.wait(0.2)
    if server:
        server.timeout = 0.5
        while not stop.is_set():
            server.handle_request()
        server.server_close()


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
    threading.Thread(target=sync_server, args=(stop,), daemon=True).start()
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
