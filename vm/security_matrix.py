#!/usr/bin/env python3
"""Print the gate matrix of finished XP25 security-lab runs as a Markdown table.

It only reads each run's results.json (written by vm/security_results.py); it
decides nothing itself. usage: security_matrix.py RUN [RUN ...]"""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vm'))
import security_paths

RUNS = security_paths.RUNS


def main():
    names = sys.argv[1:]
    if not names:
        raise SystemExit(__doc__)
    records = [json.loads((RUNS / name / 'results.json').read_text()) for name in names]
    order = []
    for record in records:
        for gate in record['gates']:
            if gate['gate'] not in order:
                order.append(gate['gate'])
    print('| Gate | ' + ' | '.join('`%s`' % name for name in names) + ' |')
    print('| --- |' + ' --- |' * len(names))
    print('| role / mode | ' + ' | '.join('%s / %s' % (r['role'], r['mode']) for r in records) + ' |')
    for gate in order:
        cells = []
        for record in records:
            found = [g for g in record['gates'] if g['gate'] == gate]
            cells.append('—' if not found else 'pass' if found[0]['passed'] else '**FAIL**')
        print('| %s | %s |' % (gate.replace('_', ' '), ' | '.join(cells)))
    print('| **all gates** | ' + ' | '.join('**%s** (%d)' % ('pass' if r['all_passed'] else 'FAIL', len(r['gates'])) for r in records) + ' |')
    print('| frozen disk SHA-256 | ' + ' | '.join('`%s…`' % (r.get('disk_sha256') or '?')[:12] for r in records) + ' |')


if __name__ == '__main__':
    main()
