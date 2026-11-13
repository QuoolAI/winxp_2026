#!/usr/bin/env python3
"""Cross-compile the XP25 security components (XP25Sec.exe, XP25Audit.exe)
and the guest security probe with the private MinGW toolchain.

Every import is checked against the export table of the guest's own system
DLLs (a read-only extraction from the verified engineering image), the PE
headers must declare NT 5.1, and no MinGW runtime may be imported. This is
compile-time evidence only: the native NT toolchain build is separate
(build/prepare_security.py) and behavior needs a recorded guest.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
S = REPO / 'components/security'
sys.path.insert(0, str(REPO / 'build'))

TARGETS = {
    'XP25Sec.exe': {'dir': S / 'xp25sec', 'entry': '_XP25SecMain',
                    'libs': ['kernel32', 'advapi32', 'user32', 'shell32', 'msvcrt']},
    'XP25Audit.exe': {'dir': S / 'xp25audit', 'entry': '_XP25AuditMain',
                      'libs': ['kernel32', 'advapi32', 'user32', 'shell32', 'netapi32', 'psapi', 'iphlpapi', 'ole32',
                               'oleaut32', 'uuid', 'msvcrt']},
}
PROBE = REPO / 'tests/guest/security_probe.c'
PROBE_LIBS = ['kernel32', 'advapi32', 'user32', 'netapi32', 'shell32', 'userenv', 'ws2_32', 'msvcrt']


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def guest_exports(modules, name):
    from inspect_component import PE
    from userenv_sp3_compat import exports
    names, _ = exports(PE(modules / name))
    return set(names)


def verify(objdump, binary, modules):
    text = subprocess.check_output([objdump, '-p', str(binary)], text=True)
    if 'file format pei-i386' not in text:
        raise ValueError(binary.name + ': not an i386 PE')
    for kind in ('OSystem', 'Subsystem'):
        major = re.search(r'^Major' + kind + r'Version\s+(\d+)\s*$', text, re.M)
        minor = re.search(r'^Minor' + kind + r'Version\s+(\d+)\s*$', text, re.M)
        if not major or not minor or (int(major[1]), int(minor[1])) > (5, 1):
            raise ValueError(binary.name + ': ' + kind + ' version is not loadable by NT 5.1')
    imports, current = {}, None
    for line in text.splitlines():
        m = re.search(r'DLL Name:\s+(\S+)', line)
        if m:
            current = m[1].lower()
            imports[current] = set()
        elif not line.strip():
            current = None
        elif current:
            e = re.fullmatch(r'\s*[0-9a-fA-F]+\s+\d+\s+([A-Za-z_]\w*)\s*', line)
            if e:
                imports[current].add(e[1])
    report = {}
    for module, symbols in imports.items():
        if module.startswith(('libgcc', 'libstdc', 'libwinpthread', 'msvcr1', 'ucrt', 'api-ms-')):
            raise ValueError(binary.name + ': forbidden runtime import ' + module)
        if not (modules / module).is_file():
            raise ValueError(binary.name + ': import from a module not extracted from the guest: ' + module)
        missing = sorted(symbols - guest_exports(modules, module))
        if missing:
            raise ValueError(binary.name + ': guest ' + module + ' lacks ' + ', '.join(missing))
        report[module] = sorted(symbols)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', type=Path, required=True, help='directory with i686-w64-mingw32-* tools')
    parser.add_argument('--guest-modules', type=Path, required=True, help='WINDOWS/system32 extracted from the verified image')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out, modules = args.output.resolve(), args.guest_modules.resolve()
    if not out.is_relative_to(REPO / '.work'):
        parser.error('output must be a fresh .work/ directory')
    out.mkdir(parents=True, exist_ok=False)
    tc = args.toolchain.resolve()
    cc, windres, objdump = (str(tc / n) for n in ('i686-w64-mingw32-gcc-posix', 'i686-w64-mingw32-windres',
                                                   'i686-w64-mingw32-objdump'))
    cflags = ['-std=gnu89', '-Os', '-Wall', '-Wextra', '-Werror', '-Wno-overlength-strings', '-Wno-cast-function-type',
              '-Wno-missing-field-initializers', '-D_WIN32_WINNT=0x0501', '-DWINVER=0x0501', '-D_WIN32_IE=0x0600',
              '-DUNICODE', '-D_UNICODE', '-fno-stack-protector', '-fno-asynchronous-unwind-tables', '-I', str(S / 'core'), '-I', str(S / 'native')]
    link = ['-nostdlib', '-nostartfiles', '-Wl,--subsystem,console:5.1', '-Wl,--major-os-version,5,--minor-os-version,1',
            '-Wl,--no-insert-timestamp', '-Wl,--disable-dynamicbase', '-Wl,--nxcompat']
    result = {'schema': 1, 'started_utc': datetime.now(timezone.utc).isoformat(), 'status': 'failed', 'targets': {},
              'toolchain': {'cc': cc, 'cc_sha256': digest(cc)}, 'guest_modules': str(modules),
              'scope': 'MinGW cross-compile and static import checks only; not a native NT build or a guest run.'}
    env = {**os.environ, 'LC_ALL': 'C'}
    try:
        for name, target in TARGETS.items():
            log = out / (name + '.log')
            objects = []
            sources = [target['dir'] / 'main.c', S / 'core/sec_core.c', S / 'native/sec_win.c']
            with log.open('a') as f:
                for source in sources:
                    obj = out / 'obj' / name / (source.stem + '.o')
                    obj.parent.mkdir(parents=True, exist_ok=True)
                    subprocess.run([cc] + cflags + ['-c', str(source), '-o', str(obj)], check=True, stdout=f,
                                   stderr=subprocess.STDOUT, env=env, timeout=120)
                    objects.append(str(obj))
                rc = next(target['dir'].glob('*.rc'))
                res = out / 'obj' / name / 'resources.o'
                subprocess.run([windres, '--preprocessor', cc, '--preprocessor-arg=-E', '--preprocessor-arg=-xc-header',
                                '--preprocessor-arg=-DRC_INVOKED', '-i', str(rc), '-o', str(res)], check=True, stdout=f,
                               stderr=subprocess.STDOUT, env=env)
                objects.append(str(res))
                subprocess.run([cc] + link + ['-Wl,--entry,' + target['entry'], '-o', str(out / name)] + objects +
                               ['-l' + l for l in target['libs']] + ['-lgcc'], check=True, stdout=f,
                               stderr=subprocess.STDOUT, env=env, timeout=120)
            result['targets'][name] = {'sha256': digest(out / name), 'bytes': (out / name).stat().st_size,
                                       'imports': verify(objdump, out / name, modules),
                                       'sources': {str(s.relative_to(REPO)): digest(s) for s in sources}}
        if PROBE.is_file():
            probe = out / 'security_probe.exe'
            with (out / 'security_probe.log').open('w') as f:
                subprocess.run([cc] + cflags + link + ['-Wl,--entry,_ProbeMain@0', str(PROBE), str(S / 'core/sec_core.c'),
                                                       '-o', str(probe)] + ['-l' + l for l in PROBE_LIBS] + ['-lgcc'],
                               check=True, stdout=f, stderr=subprocess.STDOUT, env=env, timeout=120)
            result['targets']['security_probe.exe'] = {'sha256': digest(probe), 'imports': verify(objdump, probe, modules),
                                                       'source_sha256': digest(PROBE)}
        result['status'] = 'compiled_static_checks_passed'
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        result['error'] = str(error)
    result['finished_utc'] = datetime.now(timezone.utc).isoformat()
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'targets'}, indent=2))
    for name, target in result['targets'].items():
        print(name, target['sha256'], sorted(target['imports']))
    return 0 if result['status'] == 'compiled_static_checks_passed' else 2


if __name__ == '__main__':
    raise SystemExit(main())
