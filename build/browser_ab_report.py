#!/usr/bin/env python3
"""Summarize a watch-ab diagnostic run per tagged block, from collected logs.

Inputs are the frozen run directory (serial log, JavaScript receipts) and the
output of collect_browser_diagnostics.py. Exceptions are attributed to a module
and RVA only from that process's own logged module bases. Nothing is inferred
from an exit code alone; unknown sites stay unknown.
"""
import argparse
import json
from pathlib import Path
import re

# Official 150.0.7871.255 PDB (GUID AA391345-1A73-D532-4C4C-44205044422E, age 1).
KNOWN_SITES = {('chrome.dll', 0x77b96f8): 'CompletionIOPortThread::ThreadMain CHECK (file_path_watcher_win.cc:357)',
               ('chrome.dll', 0x842214): 'base::win::TakeHandleOfType CHECK (scoped_handle.cc:77)'}
# Crashpad termination codes (third_party/crashpad/util/win/termination_codes.h).
CRASHPAD = {0xffff7001: 'crashpad_crash_no_dump', 0xffff7002: 'crashpad_snapshot_failed',
            0xffff7003: 'crashpad_not_connected'}
FIELD = re.compile(r'(\w+)=(\S+)')


def fields(line):
    return dict(FIELD.findall(line))


def block(log):
    modules, rows = {}, {'cycles': {}, 'exceptions': [], 'abnormal_exits': [], 'deadlines': 0}
    for line in log.read_text(errors='replace').splitlines():
        kind = line.split(' ', 1)[0]
        f = fields(line)
        if kind == 'MODULE':
            path = line.split(' path=', 1)[1] if ' path=' in line else ''
            modules.setdefault(f['pid'], []).append((int(f['base'], 16), int(f['size'], 16), path.rsplit('\\', 1)[-1].lower()))
        elif kind == 'EXCEPTION':
            address = int(f['address'], 16)
            site = next(((name, address - base) for base, size, name in modules.get(f['pid'], [])
                         if base <= address < base + size), None)
            rows['exceptions'].append({'cycle': int(f['cycle']), 'pid': int(f['pid']), 'code': f['code'],
                                       'first_chance': f['first'] == '1', 'module': site and site[0],
                                       'rva': site and hex(site[1]), 'identified': KNOWN_SITES.get(site)})
        elif kind in ('PROCESS_EXIT', 'PLAIN_PROCESS_EXIT'):
            code = int(f['code'], 16)
            if code:
                rows['abnormal_exits'].append({'cycle': int(f['cycle']), 'pid': int(f['pid']), 'root': f['root'] == '1',
                                               'code': hex(code), 'meaning': CRASHPAD.get(code)})
        elif kind in ('CYCLE_EXIT', 'PLAIN_CYCLE_EXIT'):
            rows['cycles'][int(f['cycle'])] = {'root_code': f['root_code'], 'elapsed_ms': int(f['elapsed_ms'])}
        elif kind in ('DEADLINE', 'PLAIN_DEADLINE'):
            rows['deadlines'] += 1
        elif kind == 'RUN_SUMMARY':
            rows['summary'] = f
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', type=Path, required=True)
    p.add_argument('--collected', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    serial = (a.run / 'serial.log').read_text(errors='replace').replace('\r', '')
    markers = dict(re.findall(r'^(XP25_[A-Z0-9_]+)=(-?\d+)\s*$', serial, re.M))
    receipts = []
    if (a.run / 'browser-js-results.jsonl').exists():
        receipts = [json.loads(r)['result'] for r in (a.run / 'browser-js-results.jsonl').read_text().splitlines()]
    report = {'run': str(a.run), 'markers': markers,
              'watch_probe': [l for l in serial.splitlines() if l.startswith('WATCH')], 'blocks': {}}
    for log in sorted(a.collected.glob('*-events.log')):
        tag = log.name[:-len('-events.log')]
        rows = block(log)
        rows['layout_verified'] = markers.get('XP25_AB_LAYOUT_' + tag.upper()) == '0'
        good = [r for r in receipts if 'run=' + tag + '-' in r.get('source', '') and r.get('checks') and all(r['checks'].values())]
        rows['passing_js_receipts'] = len(good)
        rows['watcher_check_hits'] = sum(1 for e in rows['exceptions'] if e['rva'] == hex(0x77b96f8) and e['module'] == 'chrome.dll')
        rows['clean_cycles'] = sum(1 for c in rows['cycles'].values() if int(c['root_code'], 16) == 0)
        report['blocks'][tag] = rows
    a.output.write_text(json.dumps(report, indent=2) + '\n')
    for tag, rows in report['blocks'].items():
        print('%-8s layout=%s cycles=%d clean_root=%d receipts=%d abnormal_exits=%d exceptions=%d watcher_check=%d deadlines=%d' % (
            tag, rows['layout_verified'], len(rows['cycles']), rows['clean_cycles'], rows['passing_js_receipts'],
            len(rows['abnormal_exits']), len(rows['exceptions']), rows['watcher_check_hits'], rows['deadlines']))


if __name__ == '__main__':
    main()
