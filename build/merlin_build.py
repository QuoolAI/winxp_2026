#!/usr/bin/env python3
"""Cross-compile MerlinAI (MerlinClient.dll, MerlinAI.exe, MerlinCrash.exe,
MerlinAI.cpl, MerlinTest.exe) with the private MinGW toolchain for static
checks and quick guest iteration.

Every import is verified against the export table of the guest's own system
DLLs (a read-only extraction from the image the binaries are for), PE headers
must declare NT 5.1, and no MinGW or C++ runtime may be imported. This is
compile-time evidence only; the native NT toolchain build is separate
(build/prepare_merlin.py) and runtime behaviour needs a recorded guest.

usage: merlin_build.py --toolchain .work/toolchains/mingw-binutils/usr/bin --output .work/<fresh>
                       [--guest-modules <...>/WINDOWS/system32]"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
M = REPO / 'components/merlin'
SHA = REPO / 'components/xp25-agent/llm/xp25_sha256.c'
CORE = [M / 'core' / n for n in ('merlin_text.c', 'merlin_record.c', 'merlin_classify.c', 'merlin_redact.c',
                                 'merlin_json.c', 'merlin_proto.c')] + [SHA]
CLIENT = [M / 'client' / n for n in ('dllmain.c', 'mc_util.c', 'mc_config.c', 'mc_queue.c', 'mc_collect.c', 'mc_http.c', 'mc_policy.c')]
SYSTEM_LIBS = ['kernel32', 'user32', 'gdi32', 'advapi32', 'shell32', 'ole32', 'oleaut32', 'comctl32', 'ws2_32', 'psapi',
               'version', 'msvcrt']

TARGETS = {
    'MerlinClient.dll': {'sources': CORE + CLIENT, 'def': M / 'client/MerlinClient.def', 'rc': M / 'client/MerlinClient.rc',
                         'dll': True, 'entry': '_DllMain@12',
                         'libs': ['kernel32', 'user32', 'advapi32', 'shell32', 'ws2_32', 'msvcrt']},
    'MerlinCrash.exe': {'sources': [M / 'crash/crash.c'], 'rc': M / 'crash/crash.rc',
                        'libs': ['kernel32', 'user32', 'advapi32', 'shell32', 'psapi', 'version', 'msvcrt'], 'client': True},
    'MerlinAI.exe': {'sources': [M / 'app' / n for n in ('main.c', 'ui.c', 'dialogs.c', 'install.c', 'character.c')],
                     'rc': M / 'app/app.rc',
                     'libs': ['kernel32', 'user32', 'gdi32', 'advapi32', 'shell32', 'ole32', 'oleaut32', 'comctl32', 'msvcrt'],
                     'client': True},
    'MerlinAI.cpl': {'sources': [M / 'cpl/cpl.c'], 'rc': M / 'cpl/cpl.rc', 'def': M / 'cpl/MerlinAI.def', 'dll': True,
                     'entry': '_DllMain@12', 'libs': ['kernel32', 'user32', 'advapi32', 'shell32', 'msvcrt']},
    'MerlinSvc.exe': {'sources': [M / 'svc/svc.c'], 'rc': M / 'svc/svc.rc', 'libs': ['kernel32', 'advapi32', 'msvcrt'], 'client': True},
    'MerlinTest.exe': {'sources': [M / 'testapp/merlintest.c'], 'rc': M / 'testapp/merlintest.rc',
                       'libs': ['kernel32', 'user32', 'msvcrt']},
}
# Lab probe only: never part of an installation.
TARGETS['merlin_probe.exe'] = {'sources': [REPO / 'tests/guest/merlin_probe.c'], 'libs': ['kernel32', 'user32', 'shell32', 'ole32', 'msvcrt'],
                               'test_only': True}
ORDER = ['MerlinClient.dll', 'MerlinCrash.exe', 'MerlinAI.exe', 'MerlinAI.cpl', 'MerlinSvc.exe', 'MerlinTest.exe', 'merlin_probe.exe']
GUEST_MODULES = REPO / '.work/merlin-20261121/guest-modules-82/WINDOWS/system32'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def merlin_icon(out):
    """Original XP25 artwork: a blue wizard's hat with stars (not the Agent character)."""
    sys.path.insert(0, str(REPO / 'build'))
    from ai_build import dib_icon
    from PIL import Image, ImageDraw

    def hat(size):
        im = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        d = ImageDraw.Draw(im)
        s = size / 32
        d.polygon([(16 * s, 1 * s), (5 * s, 25 * s), (27 * s, 25 * s)], fill=(40, 70, 170, 255), outline=(15, 30, 90, 255))
        d.ellipse([2 * s, 22 * s, 30 * s, 30 * s], fill=(30, 55, 140, 255), outline=(15, 30, 90, 255))
        for x, y in ((14, 10), (18, 16), (11, 19)):
            d.polygon([(x * s, (y - 2) * s), ((x + 1) * s, y * s), (x * s, (y + 2) * s), ((x - 1) * s, y * s)], fill=(255, 220, 60, 255))
        return im
    out.write_bytes(dib_icon([hat(48).resize((n, n), 1) for n in (16, 32, 48)]))


def message_table(out):
    """RT_MESSAGETABLE with one Unicode entry, id 1 = "%1\\r\\n" (MerlinLogEvent)."""
    text = '%1\r\n\0'.encode('utf-16-le')
    while (4 + len(text)) % 4:
        text += b'\0'
    entry = struct.pack('<HH', 4 + len(text), 1) + text
    out.write_bytes(struct.pack('<I', 1) + struct.pack('<III', 1, 1, 16) + entry)


def resources(res):
    res.mkdir(parents=True, exist_ok=True)
    merlin_icon(res / 'merlin.ico')
    message_table(res / 'merlinmsg.bin')
    (res / 'merlin.manifest').write_bytes((M / 'merlin.manifest').read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--toolchain', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--guest-modules', type=Path)
    args = parser.parse_args()
    global GUEST_MODULES
    if args.guest_modules:
        GUEST_MODULES = args.guest_modules.resolve()
    out = args.output.resolve()
    if not out.is_relative_to(REPO / '.work'):
        parser.error('output must be a fresh .work/ directory')
    out.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(REPO / 'build'))
    import ai_build
    ai_build.GUEST_MODULES = GUEST_MODULES
    tc = args.toolchain.resolve()
    cc, windres, objdump = (str(tc / n) for n in ('i686-w64-mingw32-gcc-posix', 'i686-w64-mingw32-windres', 'i686-w64-mingw32-objdump'))
    res = out / 'res'
    resources(res)
    cflags = ['-std=gnu89', '-Os', '-Wall', '-Wextra', '-Werror', '-Wno-overlength-strings', '-Wno-cast-function-type',
              '-Wno-missing-field-initializers', '-D_WIN32_WINNT=0x0501', '-DWINVER=0x0501', '-D_WIN32_IE=0x0600',
              '-DUNICODE', '-D_UNICODE', '-fno-stack-protector', '-fno-asynchronous-unwind-tables', '-fno-omit-frame-pointer']
    result = {'schema': 1, 'started_utc': datetime.now(timezone.utc).isoformat(), 'status': 'failed', 'targets': {},
              'toolchain': {'cc': cc, 'cc_sha256': digest(cc)}, 'guest_modules': str(GUEST_MODULES),
              'scope': 'MinGW cross-compile and static import checks only; not a native NT build or guest run.'}
    env = {**os.environ, 'LC_ALL': 'C'}
    try:
        for name in ORDER:
            t = TARGETS[name]
            objs, log = [], out / (name + '.log')
            for src in t['sources']:
                obj = out / 'obj' / name / (src.stem + '.o')
                obj.parent.mkdir(parents=True, exist_ok=True)
                with log.open('a') as f:
                    subprocess.run([cc] + cflags + ['-c', str(src), '-o', str(obj)], check=True, stdout=f, stderr=subprocess.STDOUT,
                                   env=env, timeout=180)
                objs.append(str(obj))
            if t.get('rc'):
                rcobj = out / 'obj' / name / 'resources.o'
                with log.open('a') as f:
                    subprocess.run([windres, '--preprocessor', cc, '--preprocessor-arg=-E', '--preprocessor-arg=-xc-header',
                                    '--preprocessor-arg=-DRC_INVOKED', '-I', str(res), '-I', str(Path(t['rc']).parent),
                                    '-i', str(t['rc']), '-o', str(rcobj)], check=True, stdout=f, stderr=subprocess.STDOUT, env=env)
                objs.append(str(rcobj))
            binary = out / name
            link = [cc, '-nostdlib', '-nostartfiles', '-Wl,--major-os-version,5,--minor-os-version,1',
                    '-Wl,--major-subsystem-version,5,--minor-subsystem-version,1', '-Wl,--no-insert-timestamp',
                    '-Wl,--disable-dynamicbase', '-Wl,--nxcompat', '-o', str(binary)]
            if t.get('dll'):
                link += ['-shared', '-Wl,--entry,' + t['entry'], '-Wl,--kill-at', '-Wl,--enable-stdcall-fixup', str(t['def']),
                         '-Wl,--out-implib,' + str(out / (binary.stem + '.lib'))]
            else:
                stub = out / 'obj' / name / 'entry.o'
                with log.open('a') as f:
                    subprocess.run([cc] + cflags + ['-c', str(REPO / 'build/ai_mingw_entry.c'), '-o', str(stub)], check=True, stdout=f,
                                   stderr=subprocess.STDOUT, env=env)
                objs.append(str(stub))
                link += ['-mwindows', '-Wl,--entry,_XP25MingwEntry@0']
            link += objs
            if t.get('client'):
                link.append(str(out / 'MerlinClient.lib'))
            link += ['-l' + l for l in t['libs']] + ['-lgcc']
            with log.open('a') as f:
                subprocess.run(link, check=True, stdout=f, stderr=subprocess.STDOUT, env=env, timeout=180)
            local = {}
            if t.get('client'):
                local['merlinclient.dll'] = set(l.strip() for l in (M / 'client/MerlinClient.def').read_text().splitlines()[2:] if l.strip())
            imports = ai_build.verify(objdump, binary, local)
            result['targets'][name] = {'sha256': digest(binary), 'bytes': binary.stat().st_size, 'imports': imports,
                                       'sources': {str(s.relative_to(REPO)): digest(s) for s in t['sources']}}
        result['status'] = 'compiled_static_checks_passed'
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        result['error'] = str(error)
    result['finished_utc'] = datetime.now(timezone.utc).isoformat()
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'targets'}, indent=2))
    for name, t in result['targets'].items():
        print(name, t['sha256'][:16], t['bytes'], sorted(t['imports']))
    return 0 if result['status'] == 'compiled_static_checks_passed' else 2


if __name__ == '__main__':
    raise SystemExit(main())
