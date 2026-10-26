#!/usr/bin/env python3
"""Report Application Error/Hang records from an extracted NT 5.1 AppEvent.Evt.

Parses only EVENTLOGRECORD headers and their insertion strings (bounded by each
record's own length). No user data beyond the event strings is read.
"""
import argparse
import json
from pathlib import Path
import struct

SOURCES = {'Application Error', 'Application Hang'}


def records(data):
    at = 0
    while True:
        at = data.find(b'LfLe', at)
        if at < 4:
            return
        start = at - 4
        length = struct.unpack_from('<I', data, start)[0]
        if not 56 <= length <= len(data) - start:
            at += 4
            continue
        (number, created, _, event_id, event_type, strings, _, _, _, string_offset) = struct.unpack_from('<IIIIHHHHII', data, start + 8)
        body = data[start:start + length]
        source_end = body.find(b'\0\0', 56)
        while source_end != -1 and (source_end - 56) % 2:
            source_end = body.find(b'\0\0', source_end + 1)
        source = body[56:source_end].decode('utf-16le', 'replace') if source_end > 56 else ''
        values, cursor = [], string_offset
        for _ in range(min(strings, 16)):
            end = cursor
            while end + 1 < length and body[end:end + 2] != b'\0\0':
                end += 2
            values.append(body[cursor:end].decode('utf-16le', 'replace'))
            cursor = end + 2
        yield {'record': number, 'created': created, 'event_id': event_id & 0xffff, 'type': event_type,
               'source': source, 'strings': values}
        at = start + length


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('evt', type=Path)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    rows = [r for r in records(a.evt.read_bytes()) if r['source'] in SOURCES]
    a.output.write_text(json.dumps(rows, indent=2) + '\n')
    for r in rows:
        print(r['record'], r['event_id'], r['source'], ' | '.join(r['strings'])[:220])


if __name__ == '__main__':
    main()
