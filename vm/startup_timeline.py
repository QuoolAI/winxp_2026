#!/usr/bin/env python3
"""Start-up phases of finished security-lab runs, from the host-side serial timeline
(serial-timeline.jsonl, written by vm/security_lab.py wait) and the QMP journal. Times are seconds
after the guest was resumed (the QMP RESUME event) and carry the timeline's 2 s poll granularity;
"logon submitted" is when the lab typed the password, which depends on the harness, so the logon
itself is measured from that point. Read-only.

usage: startup_timeline.py RUN_DIR [RUN_DIR ...]   prints one JSON record per run"""
import datetime
import json
from pathlib import Path
import sys

EVENTS = (('winlogon_entry', '"xp25_winlogon":"entry"'), ('gina_initialized', '"xp25_winlogon":"gina_initialized"'),
          ('logon_prompt_ready', '"xp25_winlogon":"core_ready"'), ('profile_loaded', '"xp25_winlogon":"profile_loaded"'),
          ('licensing_allowed', '"xp25_winlogon":"licensing_policy_allowed"'),
          ('session_interactive', '"xp25_winlogon":"session_interactive"'))


def when(text):
    return datetime.datetime.fromisoformat(text)


def phases(run):
    run = Path(run)
    resume = submitted = None
    for line in (run / 'journal.jsonl').read_text().splitlines():
        record = json.loads(line)
        event = record.get('event')
        if resume is None and isinstance(event, dict) and event.get('event') == 'RESUME':
            resume = when(record['utc'])
        if submitted is None and record.get('logon_keys_sent'):
            submitted = when(record['utc'])
    first = {}
    timeline = run / 'serial-timeline.jsonl'
    if resume is None or not timeline.is_file():
        return {'run': run.name, 'timeline': False}
    for line in timeline.read_text().splitlines():
        record = json.loads(line)
        for name, needle in EVENTS:
            if name not in first and needle in record['line']:
                # Logon events seen before the password was typed belong to the logon screen, not the logon.
                if name in ('profile_loaded', 'licensing_allowed', 'session_interactive') and submitted and when(record['utc']) < submitted:
                    continue
                first[name] = when(record['utc'])
        if 'desktop_fixture' not in first and record['line'].startswith('XP25_') and 'session_interactive' in first:
            first['desktop_fixture'] = when(record['utc'])
    result = {'run': run.name, 'timeline': True}
    for name, stamp in first.items():
        result[name] = round((stamp - resume).total_seconds(), 1)
    if submitted:
        result['logon_submitted'] = round((submitted - resume).total_seconds(), 1)
        if 'session_interactive' in first:
            result['logon_to_interactive'] = round((first['session_interactive'] - submitted).total_seconds(), 1)
    return result


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    for run in sys.argv[1:]:
        print(json.dumps(phases(run)))


if __name__ == '__main__':
    main()
