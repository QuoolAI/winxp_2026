#!/usr/bin/env python3
"""Cross-compile the XP25 AI components (ClippyAI, RoverAI, the RoverAI
Explorer bar, the shared xp25agent.dll and XP25Broker) with the private MinGW
toolchain for static checks and quick guest iteration.

Each import is verified against the export table of the guest's own system
DLLs (a read-only extraction from the accepted engineering image), PE headers
must declare NT 5.1, and no MinGW/C++ runtime may be imported. This is
compile-time evidence only; the native NT toolchain build is separate
(build/prepare_ai.py) and runtime behavior needs a recorded guest.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
C = REPO / 'components'
A = C / 'xp25-agent'
R = C / 'roverai'
K = C / 'clippyai'

CORE = [A / 'runtime/xp25_base.c', A / 'runtime/xp25_json.c', A / 'runtime/xp25_agent.c', A / 'llm/xp25_sha256.c',
        A / 'llm/xp25_llm.c', A / 'llm/xp25_offline.c', A / 'permissions/xp25_policy.c', R / 'indexer/rover_index.c',
        R / 'search/rover_query.c']
NATIVE = [A / 'runtime/xp25_win.c', A / 'runtime/xp25_msagent.c', A / 'llm/xp25_http.c', A / 'llm/xp25_provider_win.c',
          A / 'ipc/xp25_ipc_win.c', A / 'dll/dllmain.c', R / 'indexer/rover_win.c'] + \
         sorted((A / 'tools').glob('win_*.c'))

TARGETS = {
    'xp25agent.dll': {'sources': CORE + NATIVE, 'def': A / 'dll/xp25agent.def', 'rc': A / 'dll/xp25agent.rc', 'dll': True,
                      'entry': '_DllMain@12',
                      'libs': ['kernel32', 'user32', 'gdi32', 'advapi32', 'shell32', 'ole32', 'oleaut32', 'ws2_32',
                               'iphlpapi', 'crypt32', 'psapi', 'msvcrt']},
    'ClippyAI.exe': {'sources': [K / 'app/main.c', K / 'ui/chatview.c', K / 'ui/dialogs.c', K / 'mascot/mascot.c',
                                 K / 'mascot/paperclip.c', K / 'chat/controller.c'], 'rc': K / 'app/clippyai.rc',
                     'libs': ['kernel32', 'user32', 'gdi32', 'advapi32', 'shell32', 'ole32', 'comctl32', 'comdlg32', 'msvcrt']},
    'RoverAI.exe': {'sources': [R / 'app/main.c', R / 'explorer/panel.c'], 'rc': R / 'app/roverai.rc',
                    'libs': ['kernel32', 'user32', 'gdi32', 'shell32', 'ole32', 'comctl32', 'msvcrt']},
    'RoverAIBand.dll': {'sources': [R / 'explorer/band.c', R / 'explorer/panel.c'], 'rc': R / 'explorer/roverband.rc',
                        'def': R / 'explorer/roverband.def', 'dll': True, 'entry': '_DllMain@12',
                        'libs': ['kernel32', 'user32', 'gdi32', 'advapi32', 'shell32', 'ole32', 'comctl32', 'msvcrt']},
    'XP25Broker.exe': {'sources': [A / 'broker/broker.c'], 'rc': A / 'broker/XP25Broker.rc',
                       'libs': ['kernel32', 'advapi32', 'shell32', 'msvcrt']},
}
GUEST_MODULES = REPO / '.work/ai-20261025/guest-modules-01/WINDOWS/system32'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def icons(out):
    """Original XP25 artwork: a paperclip for ClippyAI and a magnifier with a dog's ear for RoverAI."""
    from PIL import Image, ImageDraw
    def clip(size):
        im = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        d = ImageDraw.Draw(im)
        s = size / 32
        w = max(1, int(3 * s))
        for color, off in (((90, 95, 110, 255), 0), ((200, 205, 215, 255), -max(1, int(s)))):
            d.arc([9 * s + off, 2 * s + off, 23 * s + off, 14 * s + off], 180, 360, fill=color, width=w)
            d.line([9 * s + off, 8 * s + off, 9 * s + off, 26 * s + off], fill=color, width=w)
            d.arc([9 * s + off, 20 * s + off, 21 * s + off, 30 * s + off], 0, 180, fill=color, width=w)
            d.line([21 * s + off, 25 * s + off, 21 * s + off, 11 * s + off], fill=color, width=w)
            d.line([23 * s + off, 8 * s + off, 23 * s + off, 20 * s + off], fill=color, width=w)
        d.ellipse([11 * s, 9 * s, 15 * s, 13 * s], fill=(255, 255, 255, 255), outline=(0, 0, 0, 255))
        d.ellipse([17 * s, 9 * s, 21 * s, 13 * s], fill=(255, 255, 255, 255), outline=(0, 0, 0, 255))
        return im
    def rover(size):
        im = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        d = ImageDraw.Draw(im)
        s = size / 32
        d.polygon([(5 * s, 4 * s), (11 * s, 2 * s), (9 * s, 12 * s)], fill=(140, 90, 40, 255))
        d.ellipse([4 * s, 4 * s, 22 * s, 22 * s], outline=(30, 80, 160, 255), width=max(2, int(3 * s)), fill=(210, 230, 255, 200))
        d.line([19 * s, 19 * s, 29 * s, 29 * s], fill=(120, 80, 30, 255), width=max(2, int(4 * s)))
        return im
    out.mkdir(parents=True, exist_ok=True)
    for name, draw in (('clippyai.ico', clip), ('roverai.ico', rover)):
        (out / name).write_bytes(dib_icon([draw(48).resize((n, n), 1) for n in (16, 32, 48)]))


def dib_icon(images):
    """ICO with classic 32-bpp DIB images and AND masks. XP-era rc.exe rejects,
    and Windows XP cannot display, the PNG-compressed images Pillow writes."""
    import struct
    entries, blobs = [], []
    offset = 6 + 16 * len(images)
    for im in images:
        w, h = im.size
        px = im.convert('RGBA').load()
        xor = b''.join(bytes((px[x, y][2], px[x, y][1], px[x, y][0], px[x, y][3])) for y in range(h - 1, -1, -1) for x in range(w))
        stride = ((w + 31) // 32) * 4
        mask = bytearray()
        for y in range(h - 1, -1, -1):
            row = bytearray(stride)
            for x in range(w):
                if px[x, y][3] < 128:
                    row[x // 8] |= 0x80 >> (x % 8)
            mask += row
        header = struct.pack('<IiiHHIIiiII', 40, w, h * 2, 1, 32, 0, len(xor) + len(mask), 0, 0, 0, 0)
        blob = header + xor + bytes(mask)
        entries.append(struct.pack('<BBBBHHII', w % 256, h % 256, 0, 0, 1, 32, len(blob), offset))
        blobs.append(blob)
        offset += len(blob)
    return struct.pack('<HHH', 0, 1, len(images)) + b''.join(entries) + b''.join(blobs)


def guest_exports(name):
    sys.path.insert(0, str(REPO / 'build'))
    from inspect_component import PE
    from userenv_sp3_compat import exports
    names, _ = exports(PE(GUEST_MODULES / name))
    return set(names)


def verify(objdump, binary, allowed_local, exact_51=True):
    text = subprocess.check_output([objdump, '-p', str(binary)], text=True)
    if 'file format pei-i386' not in text:
        raise ValueError(binary.name + ': not an i386 PE')
    for kind in ('OSystem', 'Subsystem'):
        major = re.search(r'^Major' + kind + r'Version\s+(\d+)\s*$', text, re.M)
        minor = re.search(r'^Minor' + kind + r'Version\s+(\d+)\s*$', text, re.M)
        if not major or not minor or (int(major[1]), int(minor[1])) > (5, 1) or (exact_51 and (int(major[1]), int(minor[1])) != (5, 1)):
            raise ValueError(binary.name + ': ' + kind + ' version is not loadable by NT 5.1')
    imports, current = {}, None
    for line in text.splitlines():
        m = re.search(r'DLL Name:\s+(\S+)', line)
        if m:
            current = m[1].lower()
            imports[current] = set()
            continue
        if not line.strip():
            current = None
        elif current:
            e = re.fullmatch(r'\s*[0-9a-fA-F]+\s+\d+\s+([A-Za-z_]\w*)\s*', line)
            if e:
                imports[current].add(e[1])
    report = {}
    for module, symbols in imports.items():
        if module in allowed_local:
            available = allowed_local[module]
        else:
            if not (GUEST_MODULES / module).is_file():
                raise ValueError(binary.name + ': import from unavailable module ' + module)
            available = guest_exports(module)
        missing = sorted(symbols - available)
        if missing:
            raise ValueError(binary.name + ': ' + module + ' lacks ' + ', '.join(missing))
        report[module] = sorted(symbols)
    if any(m.startswith(('libgcc', 'libstdc', 'libwinpthread', 'msvcr1', 'ucrt', 'api-ms-')) for m in imports):
        raise ValueError(binary.name + ': forbidden runtime import')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', type=Path, required=True, help='directory with i686-w64-mingw32-* tools')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--probe', action='store_true', help='also build the guest test probe tests/guest/ai_probe.c')
    args = parser.parse_args()
    out = args.output.resolve()
    if not out.is_relative_to(REPO / '.work'):
        parser.error('output must be a fresh .work/ directory')
    out.mkdir(parents=True, exist_ok=False)
    tc = args.toolchain.resolve()
    cc, windres, objdump, dlltool = (str(tc / n) for n in ('i686-w64-mingw32-gcc-posix', 'i686-w64-mingw32-windres',
                                                            'i686-w64-mingw32-objdump', 'i686-w64-mingw32-dlltool'))
    res = out / 'res'
    icons(res)
    for rc in (K / 'app', R / 'app'):
        for f in rc.glob('*.manifest'):
            shutil.copy2(f, res / f.name)
    entry_stub = REPO / 'build/ai_mingw_entry.c'
    cflags = ['-std=gnu89', '-Os', '-Wall', '-Wextra', '-Werror', '-Wno-overlength-strings', '-Wno-cast-function-type',
              '-Wno-missing-field-initializers', '-D_WIN32_WINNT=0x0501', '-DWINVER=0x0501', '-D_WIN32_IE=0x0600',
              '-DUNICODE', '-D_UNICODE', '-fno-stack-protector', '-fno-asynchronous-unwind-tables']
    result = {'schema': 1, 'started_utc': datetime.now(timezone.utc).isoformat(), 'status': 'failed', 'targets': {},
              'toolchain': {'cc': cc, 'cc_sha256': digest(cc)}, 'guest_modules': str(GUEST_MODULES),
              'scope': 'MinGW cross-compile and static import checks only; not a native NT build or guest run.'}
    local = {'xp25agent.dll': set(l.strip() for l in (A / 'dll/xp25agent.def').read_text().splitlines()[3:] if l.strip())}
    env = {**os.environ, 'LC_ALL': 'C'}
    try:
        order = ['xp25agent.dll', 'ClippyAI.exe', 'RoverAI.exe', 'RoverAIBand.dll', 'XP25Broker.exe']
        for name in order:
            t = TARGETS[name]
            objs = []
            log = out / (name + '.log')
            for src in t['sources']:
                obj = out / 'obj' / name / (src.stem + '.o')
                obj.parent.mkdir(parents=True, exist_ok=True)
                with log.open('a') as f:
                    subprocess.run([cc] + cflags + ['-c', str(src), '-o', str(obj)], check=True, stdout=f,
                                   stderr=subprocess.STDOUT, env=env, timeout=120)
                objs.append(str(obj))
            rcobj = out / 'obj' / name / 'resources.o'
            with log.open('a') as f:
                subprocess.run([windres, '--preprocessor', cc, '--preprocessor-arg=-E', '--preprocessor-arg=-xc-header',
                                '--preprocessor-arg=-DRC_INVOKED', '-I', str(res), '-I', str(Path(t['rc']).parent),
                                '-i', str(t['rc']), '-o', str(rcobj)],
                               check=True, stdout=f, stderr=subprocess.STDOUT, env=env)
            objs.append(str(rcobj))
            binary = out / name
            link = [cc, '-nostdlib', '-nostartfiles', '-Wl,--major-os-version,5,--minor-os-version,1',
                    '-Wl,--major-subsystem-version,5,--minor-subsystem-version,1', '-Wl,--no-insert-timestamp',
                    '-Wl,--disable-dynamicbase', '-Wl,--nxcompat', '-o', str(binary)]
            if t.get('dll'):
                link += ['-shared', '-Wl,--entry,' + t['entry'], str(t['def']),
                         '-Wl,--out-implib,' + str(out / (binary.stem + '.lib'))]
            else:
                stub = out / 'obj' / name / 'entry.o'
                with log.open('a') as f:
                    subprocess.run([cc] + cflags + ['-c', str(entry_stub), '-o', str(stub)], check=True, stdout=f,
                                   stderr=subprocess.STDOUT, env=env)
                objs.append(str(stub))
                link += ['-mwindows', '-Wl,--entry,_XP25MingwEntry@0']
            link += objs
            if name != 'xp25agent.dll':
                link.append(str(out / 'xp25agent.lib'))
            link += ['-l' + l for l in t['libs']] + ['-lgcc']
            with log.open('a') as f:
                subprocess.run(link, check=True, stdout=f, stderr=subprocess.STDOUT, env=env, timeout=120)
            imports = verify(objdump, binary, local)
            result['targets'][name] = {'sha256': digest(binary), 'bytes': binary.stat().st_size, 'imports': imports,
                                       'sources': {str(s.relative_to(REPO)): digest(s) for s in t['sources']}}
        if args.probe:
            probe = out / 'ai_probe.exe'
            src = REPO / 'tests/guest/ai_probe.c'
            with (out / 'ai_probe.log').open('w') as f:
                subprocess.run([cc, '-Os', '-Wall', '-Wextra', '-Werror', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
                                '-nostdlib', '-D_WIN32_WINNT=0x0501', '-Wl,--entry,_ProbeMain@0', '-Wl,--subsystem,console:5.1',
                                '-Wl,--major-os-version,5,--minor-os-version,1', '-Wl,--no-insert-timestamp',
                                '-Wl,--disable-dynamicbase', str(src), '-o', str(probe), '-lkernel32', '-luser32',
                                '-ladvapi32', '-lshell32', '-lgcc'], check=True, stdout=f, stderr=subprocess.STDOUT, env=env)
            result['targets']['ai_probe.exe'] = {'sha256': digest(probe), 'imports': verify(objdump, probe, {}),
                                                 'source_sha256': digest(src)}
        result['status'] = 'compiled_static_checks_passed'
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        result['error'] = str(error)
    result['finished_utc'] = datetime.now(timezone.utc).isoformat()
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'targets'}, indent=2))
    for name, t in result['targets'].items():
        print(name, t['sha256'], sorted(t['imports']))
    return 0 if result['status'] == 'compiled_static_checks_passed' else 2


if __name__ == '__main__':
    raise SystemExit(main())
