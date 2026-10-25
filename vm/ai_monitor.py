#!/usr/bin/env python3
"""Watch one vm/ai_lab.py run: screenshot the guest periodically, wait for
the suite's COM1 completion marker, request a normal guest shutdown, freeze
the overlay and summarize the serial records into ai-results.json.

Gates come from the guest's own serial records, never from screenshots."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def summarize(run):
    text = (run / 'serial.log').read_bytes().decode('utf-8', 'replace').replace('\r', '')
    cases, exits, other = [], {}, []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('{"ai_case"'):
            try:
                cases.append(json.loads(line))
            except ValueError:
                other.append(line)
        m = re.match(r'^([A-Z0-9_]+_EXIT|XP25_AI_[A-Z_]+)=(\S+)', line)
        if m:
            exits[m[1]] = m[2]
    failed = [c['ai_case'] for c in cases if c['status'] != 'pass']
    regression_exits = {k: v for k, v in exits.items() if k.endswith('_PROBE_EXIT') and not k.startswith('XP25_AI')}
    result = {'cases': len(cases), 'passed': len(cases) - len(failed), 'failed': failed, 'exits': exits,
              'regression_probe_exits_all_zero': bool(regression_exits) and all(v == '0' for v in regression_exits.values()),
              'suite_done': 'XP25_AI_SUITE_DONE' in text, 'complete_marker': 'AI_PROBE_COMPLETE' in text,
              'unparsed_case_lines': other}
    (run / 'ai-results.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def lab(run, *args):
    return subprocess.run([sys.executable, str(ROOT / 'vm/xp_lab.py'), str(run), *args], capture_output=True, text=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run', type=Path)
    parser.add_argument('--timeout', type=int, default=3600)
    parser.add_argument('--interval', type=int, default=20)
    parser.add_argument('--no-shutdown', action='store_true')
    args = parser.parse_args()
    run = args.run.resolve()
    start = time.time()
    shot = 0
    while time.time() - start < args.timeout:
        text = (run / 'serial.log').read_bytes() if (run / 'serial.log').exists() else b''
        if b'XP25_AI_SUITE_DONE' in text:
            break
        lab(run, 'screen', 'progress-%03d' % shot)
        shot += 1
        time.sleep(args.interval)
    result = summarize(run)
    lab(run, 'screen', 'suite-finished')
    print(json.dumps(result, indent=2))
    if args.no_shutdown or not result['suite_done']:
        return 2
    time.sleep(10)
    down = lab(run, 'shutdown', '--settle-seconds', '3')
    (run / 'shutdown.log').write_text(down.stdout + down.stderr)
    if down.returncode:
        return 3
    fin = lab(run, 'finish')
    (run / 'finish.log').write_text(fin.stdout + fin.stderr)
    return 0 if fin.returncode == 0 and not result['failed'] and result['regression_probe_exits_all_zero'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
