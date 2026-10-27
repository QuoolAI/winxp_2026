#!/usr/bin/env python3
"""Drive a registered qemu:///system domain through libvirt's public API only
(send-key, screenshot, lifecycle events), so the domain is never tainted by
monitor commands. Every call is journaled to <evidence dir>/commands.jsonl.
QEMU UI input can be lost under load: check a screenshot before typing.
usage: libvirt_ui.py <domain> <evidence dir> key KEY_A [KEY_B ...] | type <text> | run <text>
       | screen <name> | turn-off
'turn-off' presses U in an open Turn Off Computer dialog and succeeds only on
libvirt's 'Shutdown Finished after guest request' event."""
from pathlib import Path
import datetime, json, subprocess, sys, time
URI = ['virsh', '-c', 'qemu:///system']
dom, out, action, rest = sys.argv[1], Path(sys.argv[2]).resolve(), sys.argv[3], sys.argv[4:]
BASIC = {' ': 'KEY_SPACE', '\\': 'KEY_BACKSLASH', '.': 'KEY_DOT', '/': 'KEY_SLASH', '-': 'KEY_MINUS',
         '=': 'KEY_EQUAL', ',': 'KEY_COMMA', ';': 'KEY_SEMICOLON', "'": 'KEY_APOSTROPHE'}
SHIFTED = {':': 'KEY_SEMICOLON', '"': 'KEY_APOSTROPHE', '_': 'KEY_MINUS', '>': 'KEY_DOT', '%': 'KEY_5'}


def log(entry):
    entry['utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with (out / 'commands.jsonl').open('a') as f:
        f.write(json.dumps(entry) + '\n')


def virsh(*args):
    r = subprocess.run(URI + list(args), capture_output=True, text=True)
    log({'argv': URI + list(args), 'rc': r.returncode, 'stdout': r.stdout[-2000:], 'stderr': r.stderr[-2000:]})
    if r.returncode:
        raise SystemExit(r.stderr)
    return r.stdout


def key(*names):
    virsh('send-key', dom, '--codeset', 'linux', '--holdtime', '60', *names); time.sleep(.15)


def type_text(text):
    for c in text:
        if c.isupper(): key('KEY_LEFTSHIFT', 'KEY_' + c)
        elif c in SHIFTED: key('KEY_LEFTSHIFT', SHIFTED[c])
        elif c in BASIC: key(BASIC[c])
        elif c.isascii() and c.isalnum(): key('KEY_' + c.upper())
        else: raise ValueError(c)


def screen(name):
    from PIL import Image
    virsh('screenshot', dom, '--file', str(out / (name + '.ppm')))
    Image.open(out / (name + '.ppm')).save(out / (name + '.png'))
    if list(Image.open(out / (name + '.png')).getdata()) == list(Image.open(out / (name + '.ppm')).getdata()):
        (out / (name + '.ppm')).unlink()
    return out / (name + '.png')


if action == 'key': key(*rest)
elif action == 'type': type_text(rest[0])
elif action == 'run':
    key('KEY_LEFTMETA', 'KEY_R'); time.sleep(3); key('KEY_LEFTCTRL', 'KEY_A'); type_text(rest[0]); key('KEY_ENTER')
elif action == 'screen': print(screen(rest[0]))
elif action == 'turn-off':
    # Precondition: the Turn Off Computer dialog is open (verified by screenshot).
    events = subprocess.Popen(URI + ['event', '--domain', dom, '--event', 'lifecycle', '--loop', '--timestamp', '--timeout', '300'],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(2)
    key('KEY_U')
    lines = []
    for line in events.stdout:
        lines.append(line.rstrip()); log({'lifecycle_event': line.rstrip()})
        if 'Stopped' in line:
            break
    events.terminate(); events.wait(timeout=10)
    state = virsh('domstate', dom, '--reason').strip()
    guest = any('Shutdown Finished after guest request' in l for l in lines)
    n = len(list(out.glob('shutdown-event-*.json'))) + 1
    (out / f'shutdown-event-{n:02d}.json').write_text(json.dumps({'lifecycle_events': lines, 'domstate': state,
        'guest_requested_shutdown': guest}, indent=2) + '\n')
    print(json.dumps({'guest_requested_shutdown': guest, 'domstate': state, 'events': lines}))
    raise SystemExit(0 if guest and state.startswith('shut off') else 1)
else:
    raise SystemExit('unknown action')
