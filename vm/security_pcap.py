#!/usr/bin/env python3
"""Summarize the packet capture of one XP25 security-lab run.

QEMU records every frame on the guest's network device (filter-dump in
vm/isolated_network.py), so this is what the wire carried, independent of
what the scanner's sockets reported. The capture's clock is the guest's
virtual clock, so it is segmented by the marker frames the scanner sends
around each observation (vm/security_network.py), not by time.

For every marked segment: SYNs sent to the guest and the SYN-ACKs/RSTs it
sent back to those attempts per port, datagrams to the guest and the replies
to them per port, the guest's own unicast datagrams and broadcasts per port,
and ICMP echo and unreachable counts. A reply is a packet from the guest to
the address and port an observer packet came from, from the port it went to.

usage: security_pcap.py RUN_DIRECTORY   (writes pcap-summary.json there)"""
import collections
import json
from pathlib import Path
import struct
import sys

GUEST = bytes([10, 25, 0, 10])
NETWORK = bytes([10, 25, 0])                          # every other address in it is the observer's
MARK = b'XP25-MARK:'


def frames(path):
    data = Path(path).read_bytes()
    if len(data) < 24:
        return
    magic, = struct.unpack_from('<I', data, 0)
    order = '<' if magic in (0xa1b2c3d4, 0xa1b23c4d) else '>'
    if struct.unpack_from(order + 'I', data, 0)[0] not in (0xa1b2c3d4, 0xa1b23c4d) or struct.unpack_from(order + 'I', data, 20)[0] != 1:
        raise ValueError('not an Ethernet pcap file')
    at = 24
    while at + 16 <= len(data):
        seconds, micro, captured, _ = struct.unpack_from(order + 'IIII', data, at)
        at += 16
        yield seconds + micro / 1e6, data[at:at + captured]
        at += captured


def new_segment():
    return {'frames': 0, 'tcp_syn_to_guest': collections.Counter(), 'tcp_synack_from_guest': collections.Counter(),
            'tcp_rst_from_guest': collections.Counter(), 'udp_to_guest': collections.Counter(),
            'udp_replies_from_guest': collections.Counter(), 'guest_udp_unicast_out': collections.Counter(),
            'guest_broadcast_udp': collections.Counter(),
            'icmp_echo_request_to_guest': 0, 'icmp_echo_reply_from_guest': 0, 'icmp_unreachable_from_guest': 0,
            'arp_from_guest': 0, 'guest_tcp_connections_out': 0, 'dhcp_requests_without_address': 0, '_attempts': set()}


def account(segment, frame):
    segment['frames'] += 1
    kind = frame[12:14]
    if kind == b'\x08\x06':
        if frame[22:28] != bytes.fromhex('525400250001'):
            segment['arp_from_guest'] += 1
        return
    if kind != b'\x08\x00' or len(frame) < 34:
        return
    ip = frame[14:]
    header = (ip[0] & 15) * 4
    protocol, source, target = ip[9], ip[12:16], ip[16:20]
    payload = ip[header:]
    from_guest, to_guest = source == GUEST, target == GUEST
    observer = target[:3] == NETWORK and target != GUEST and target[3] != 255
    if protocol == 6 and len(payload) >= 14:
        sport, dport = struct.unpack_from('>HH', payload, 0)
        flags = payload[13]
        if to_guest and flags & 0x12 == 0x02:
            segment['tcp_syn_to_guest'][dport] += 1
            segment['_attempts'].add((source, sport, dport))
        elif from_guest and flags & 0x12 == 0x02:
            segment['guest_tcp_connections_out'] += 1
        # Only answers to the observer's own attempts count; the guest's outbound connections
        # (its polls of the observer's sync service) end with resets of their own.
        elif from_guest and (target, dport, sport) in segment['_attempts']:
            if flags & 0x12 == 0x12:
                segment['tcp_synack_from_guest'][sport] += 1
            elif flags & 0x04:
                segment['tcp_rst_from_guest'][sport] += 1
    elif protocol == 17 and len(payload) >= 8:
        sport, dport = struct.unpack_from('>HH', payload, 0)
        if source == bytes(4) and sport == 68 and dport == 67:
            segment['dhcp_requests_without_address'] += 1      # a client starting up (or restarting) asks for its lease
        if to_guest:
            segment['udp_to_guest'][dport] += 1
            segment['_attempts'].add((source, sport, dport))
        elif from_guest and observer and (target, dport, sport) in segment['_attempts']:
            segment['udp_replies_from_guest'][sport] += 1           # an answer to a datagram the observer sent
        elif from_guest and observer:
            segment['guest_udp_unicast_out'][dport] += 1            # the guest's own traffic (DNS, DHCP renewal)
        elif from_guest and (target[3] == 255 or target == b'\xff\xff\xff\xff'):
            segment['guest_broadcast_udp'][dport] += 1
    elif protocol == 1 and len(payload) >= 2:
        if to_guest and payload[0] == 8:
            segment['icmp_echo_request_to_guest'] += 1
        elif from_guest and payload[0] == 0:
            segment['icmp_echo_reply_from_guest'] += 1
        elif from_guest and payload[0] == 3:
            segment['icmp_unreachable_from_guest'] += 1


def summarize(path):
    segments, order, open_labels, total = {}, [], [], 0
    whole = new_segment()
    for _, frame in frames(path):
        total += 1
        if frame[12:14] == b'\x88\xb5' and frame[14:14 + len(MARK)] == MARK:
            label, _, edge = frame[14 + len(MARK):].rstrip(b'\0').decode('latin-1').rpartition(':')
            if edge == 'start' and label not in segments:
                segments[label] = new_segment()
                order.append(label)
                open_labels.append(label)
            elif edge == 'end' and label in open_labels:
                open_labels.remove(label)
                segments[label]['closed'] = True
            continue
        account(whole, frame)
        for label in open_labels:
            account(segments[label], frame)

    def plain(segment):
        return {key: (dict(sorted((str(k), v) for k, v in value.items())) if isinstance(value, collections.Counter) else value)
                for key, value in segment.items() if not key.startswith('_')}
    return {'capture': str(path), 'frames': total, 'segments': {label: plain(segments[label]) for label in order}, 'whole_capture': plain(whole)}


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    run = Path(sys.argv[1])
    result = summarize(run / 'network.pcap')
    (run / 'pcap-summary.json').write_text(json.dumps(result, indent=1) + '\n')
    for label, segment in result['segments'].items():
        print(label, {k: v for k, v in segment.items() if v and k != 'frames'})
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
