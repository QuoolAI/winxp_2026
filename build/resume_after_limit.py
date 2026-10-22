#!/usr/bin/env python3
"""Resume one existing Codex session only after a recorded usage-limit reset.

Local supervisor, not an agent. It never guesses reset durations, retries ordinary
errors, or starts a second turn while the recorded session has an active turn.
"""
import argparse
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import time
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
UTC = dt.timezone.utc


def reset_time(error, rates, stamp, timezone):
    """Use server timestamps for exhausted windows, else its explicit message."""
    exhausted = [v['resets_at'] for k, v in (rates or {}).items()
                 if k in ('primary', 'secondary') and isinstance(v, dict)
                 and v.get('used_percent', 0) >= 100 and v.get('resets_at')]
    if exhausted:
        return max(exhausted)
    match = re.search(r'try again at ([^.]+)', error.get('message', ''), re.I)
    if not match:
        raise ValueError('Usage limit has no documented reset time; stopping.')
    text = re.sub(r'(\d+)(st|nd|rd|th)\b', r'\1', match[1]).strip()
    local = dt.datetime.fromisoformat(stamp.replace('Z', '+00:00')).astimezone(ZoneInfo(timezone))
    for fmt in ('%b %d, %Y %I:%M %p', '%B %d, %Y %I:%M %p'):
        try:
            return dt.datetime.strptime(text, fmt).replace(tzinfo=local.tzinfo).timestamp()
        except ValueError:
            pass
    clock = dt.datetime.strptime(text, '%I:%M %p').time()
    result = dt.datetime.combine(local.date(), clock, local.tzinfo)
    if result < local:
        result += dt.timedelta(days=1)
    return result.timestamp()


def usage_error(error):
    return isinstance(error, dict) and error.get('codex_error_info') == 'usage_limit_exceeded'


def save(directory, **state):
    target = directory / 'state.json'
    old = json.loads(target.read_text()) if target.exists() else {}
    old.update(state, updated_at=dt.datetime.now(UTC).isoformat())
    temp = directory / 'state.tmp'
    temp.write_text(json.dumps(old, indent=2) + '\n')
    os.replace(temp, target)


def supervise(session, rollout, timezone):
    directory = ROOT / '.work' / 'resumption' / session
    directory.mkdir(parents=True, exist_ok=True)
    lock = (directory / 'supervisor.lock').open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    rates = None
    # Read existing history for rate metadata only. Old failures must never
    # trigger a new execution when this watcher is first armed.
    with rollout.open() as stream:
        for line in stream:
            row = json.loads(line)
            payload = row.get('payload', {})
            if row.get('type') == 'event_msg' and payload.get('type') == 'token_count':
                rates = payload.get('rate_limits') or rates
        position = stream.tell()
    save(directory, state='watching', supervisor_pid=os.getpid(), session=session,
         rollout=str(rollout), cursor=position, active_turn=True)
    pending = None
    worker = None
    last_attempt = None
    output = None
    while True:
        with rollout.open() as stream:
            stream.seek(position)
            while True:
                begin = stream.tell()
                line = stream.readline()
                if not line or not line.endswith('\n'):
                    position = begin
                    break
                row = json.loads(line)
                position = stream.tell()
                payload = row.get('payload', {})
                if row.get('type') != 'event_msg':
                    continue
                kind = payload.get('type')
                if kind == 'token_count':
                    rates = payload.get('rate_limits') or rates
                elif kind == 'task_started':
                    pending = None
                    save(directory, state='watching', active_turn=True, cursor=position)
                elif kind == 'task_complete':
                    error = payload.get('error')
                    if not error:
                        save(directory, state='completed', active_turn=False, cursor=position)
                        return 0
                    if not usage_error(error):
                        save(directory, state='stopped_non_usage_error', error=error, active_turn=False)
                        return 1
                    reset = reset_time(error, rates, row['timestamp'], timezone)
                    identity = (payload.get('turn_id'), reset)
                    if identity == last_attempt:
                        raise RuntimeError('Duplicate usage-limit event; stopping.')
                    if last_attempt is not None and reset <= last_attempt[1]:
                        raise RuntimeError('Server has not supplied a later reset; stopping retry loop.')
                    pending = (reset, identity)
                    save(directory, state='waiting_for_reset', active_turn=False,
                         reset_at=reset, reset_utc=dt.datetime.fromtimestamp(reset, UTC).isoformat(),
                         error=error, cursor=position)
                elif kind == 'turn_aborted':
                    save(directory, state='stopped_turn_aborted', active_turn=False)
                    return 1
        if worker is not None and worker.poll() is not None:
            code = worker.returncode
            output.close()
            worker = None
            if pending is None:
                save(directory, state='stopped_cli_exit', exit_code=code,
                     active_turn=False, worker_pid=None)
                return code
        if pending and worker is None and time.time() >= pending[0] + 2:
            # Rescan at the next iteration if a user has begun another turn.
            if rollout.stat().st_size != position:
                continue
            last_attempt = pending[1]
            pending = None
            prompt = ('Continue the existing Windows XP source-kernel boot milestone. '
                      'Read docs/PROGRESS.md and .work/boot-debug-20261022/checkpoint.json '
                      'first. Reconcile running VM/build PIDs before resuming; never '
                      'duplicate a running experiment or modify the SP3 reference VM. '
                      'Continue debugging, compiling and testing until the recorded '
                      'desktop milestone succeeds or a concrete external dependency blocks it.')
            command = ['codex', 'exec', 'resume', '--json',
                       '-c', 'approval_policy="never"', '-c', 'sandbox_mode="danger-full-access"',
                       session, prompt]
            log = directory / ('resume-' + str(time.time_ns()) + '.jsonl')
            output = log.open('w')
            worker = subprocess.Popen(command, cwd=ROOT, stdout=output,
                                      stderr=subprocess.STDOUT, start_new_session=True)
            save(directory, state='resuming', worker_pid=worker.pid, command=command,
                 execution_log=str(log), active_turn=True)
        time.sleep(2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--session', required=True)
    parser.add_argument('--rollout', required=True, type=Path)
    parser.add_argument('--timezone', default='America/Los_Angeles')
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-fA-F-]{36}', args.session):
        parser.error('An explicit session UUID is required.')
    with args.rollout.open() as stream:
        meta = json.loads(stream.readline()).get('payload', {})
    if meta.get('id') != args.session or Path(meta.get('cwd', '')).resolve() != ROOT:
        parser.error('Session identity or repository does not match.')
    try:
        return supervise(args.session, args.rollout.resolve(), args.timezone)
    except (ValueError, RuntimeError) as exc:
        save(ROOT / '.work' / 'resumption' / args.session, state='stopped_error', error=str(exc))
        raise


if __name__ == '__main__':
    raise SystemExit(main())
