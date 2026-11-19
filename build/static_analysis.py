#!/usr/bin/env python3
"""Milestone 8.4 static analysis of the XP25 sources. Diagnostics only: nothing is changed, built for
the guest or installed. Three passes, each with its raw log kept:

  native   every native target from components/**/sources, compiled translation unit by
           translation unit with the private MinGW GCC (i686, Win32 headers, NT 5.1 defines) at
           -Wall -Wextra plus selected extra warnings and GCC's -fanalyzer. MinGW's headers are not the
           NT 5.1 SDK and GCC is not the guest compiler (CL 13.00 at /W4 /WX), so a diagnostic here is a
           lead for review, not a property of the shipped binary.
  portable the portable C cores (Winlogon, security, agent runtime, RoverAI index/query) with the
           host GCC at the same warnings and -fanalyzer.
  python   pyflakes over build/, vm/, tests/, remote-access/ and components/.

usage: static_analysis.py --output .work/<fresh> [--toolchain .work/toolchains/mingw-binutils/usr/bin]
writes findings.json (one record per diagnostic: pass, file, line, rule, message) and per-pass logs."""
import argparse
import collections
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import modernization_inventory as inv

WARNINGS = ['-Wall', '-Wextra', '-Wshadow', '-Wformat=2', '-Wcast-qual', '-Wpointer-arith', '-Wwrite-strings',
            '-Wnull-dereference', '-Wduplicated-cond', '-Wlogical-op', '-Wstrict-prototypes', '-Wold-style-definition',
            '-Wsign-conversion', '-Wconversion', '-Wstringop-overflow=4', '-Warray-bounds=2', '-Wimplicit-fallthrough',
            '-Wno-unknown-pragmas', '-Wno-missing-field-initializers']
ANALYZER = ['-fanalyzer', '-fdiagnostics-plain-output', '-fno-diagnostics-show-caret']
NT51 = ['-DWIN32', '-DNT', '-D_X86_=1', '-Di386=1', '-DWINVER=0x0501', '-D_WIN32_WINNT=0x0501', '-D_WIN32_IE=0x0600']
PORTABLE = {
    'winlogon-core': (['components/winlogon/state.c', 'components/winlogon/policy.c', 'components/winlogon/session_engine.c',
                       'components/winlogon/environment.c', 'components/winlogon/bootkey_codec.c'], ['-DXP25_SESSION_TEST=1']),
    'security-core': (['components/security/core/sec_core.c'], []),
    'agent-runtime': (['components/xp25-agent/runtime/xp25_base.c', 'components/xp25-agent/runtime/xp25_json.c',
                       'components/xp25-agent/runtime/xp25_agent.c', 'components/xp25-agent/permissions/xp25_policy.c',
                       'components/xp25-agent/llm/xp25_sha256.c', 'components/xp25-agent/llm/xp25_llm.c',
                       'components/xp25-agent/llm/xp25_offline.c', 'components/roverai/indexer/rover_index.c',
                       'components/roverai/search/rover_query.c'], []),
}
DIAG = re.compile(r'^(?P<file>[^:\n]+):(?P<line>\d+):(?:(?P<col>\d+):)? (?P<kind>warning|error|note): (?P<msg>.*?)(?: \[(?P<rule>-W[^\]]+)\])?$')


def parse(log, pass_name, unit):
    findings = []
    for line in log.splitlines():
        m = DIAG.match(line)
        if not m or m['kind'] == 'note':
            continue
        path = Path(m['file'])
        try:
            rel = str((ROOT / path).resolve().relative_to(ROOT)) if not path.is_absolute() else str(path.resolve().relative_to(ROOT))
        except ValueError:
            rel = str(path)
        findings.append({'pass': pass_name, 'unit': unit, 'file': rel, 'line': int(m['line']), 'kind': m['kind'],
                         'rule': m['rule'] or ('-Wanalyzer' if 'analyzer' in (m['msg'] or '') else m['kind']), 'message': m['msg']})
    return findings


def compile_unit(cc, source, flags, logdir, tag):
    obj = logdir / (tag + '.o')
    cmd = [cc, '-std=gnu99', '-O1', '-c', str(ROOT / source), '-o', str(obj)] + flags
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=str((ROOT / source).parent))
    (logdir / (tag + '.log')).write_text(' '.join(cmd) + '\n' + r.stdout + r.stderr)
    if obj.exists():
        obj.unlink()
    return r.returncode, r.stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--toolchain', type=Path, default=ROOT.parent / 'winxp_2026/.work/toolchains/mingw-binutils/usr/bin')
    args = parser.parse_args()
    out = args.output.resolve()
    if not out.is_relative_to(ROOT / '.work'):
        parser.error('private .work/ output required')
    mingw = args.toolchain / 'i686-w64-mingw32-gcc-posix'
    if not mingw.exists():
        parser.error('MinGW GCC not found: %s' % mingw)
    out.mkdir(parents=True, exist_ok=False)
    findings, units = [], []
    files = inv.tracked()
    for sources_file in [p for p in files if p.startswith('components/') and p.endswith('/sources')]:
        t = inv.parse_sources(sources_file)
        text = (ROOT / sources_file).read_text(encoding='latin-1').replace('\\\n', ' ')
        includes = re.search(r'^\s*INCLUDES\s*=\s*(.*)$', text, re.M)
        incs = ['-I' + str(((ROOT / sources_file).parent / i.replace('\\', '/')).resolve())
                for i in (includes.group(1).split(';') if includes else []) if i.strip()]
        defines = [d for d in (t['defines'] or '').split() if d.startswith('-D')]
        logdir = out / 'native' / t['target']
        logdir.mkdir(parents=True)
        for src in t['sources']:
            if not src.endswith('.c'):
                continue
            tag = Path(src).stem
            rc, err = compile_unit(str(mingw), src, NT51 + defines + incs + ['-I' + str((ROOT / sources_file).parent)] + WARNINGS + ANALYZER, logdir, tag)
            units.append({'pass': 'native', 'target': t['target'], 'source': src, 'returncode': rc})
            findings += parse(err, 'native', t['target'] + ':' + src)
    for name, (sources, defines) in PORTABLE.items():
        logdir = out / 'portable' / name
        logdir.mkdir(parents=True)
        for src in sources:
            rc, err = compile_unit('gcc', src, defines + WARNINGS + ANALYZER, logdir, Path(src).stem)
            units.append({'pass': 'portable', 'target': name, 'source': src, 'returncode': rc})
            findings += parse(err, 'portable', name + ':' + src)
    pyflakes = shutil.which('pyflakes')
    py = [p for p in files if p.endswith('.py')]
    if pyflakes:
        r = subprocess.run([pyflakes] + py, capture_output=True, text=True, cwd=str(ROOT))
        (out / 'pyflakes.log').write_text(r.stdout + r.stderr)
        for line in (r.stdout + r.stderr).splitlines():
            m = re.match(r'^([^:]+):(\d+):(?:\d+:)? (.*)$', line)
            if m:
                findings.append({'pass': 'python', 'unit': 'pyflakes', 'file': m[1], 'line': int(m[2]), 'kind': 'warning',
                                 'rule': 'pyflakes', 'message': m[3]})
    # One record per distinct diagnostic (a header seen from several units is reported once).
    unique, seen = [], set()
    for f in findings:
        key = (f['file'], f['line'], f['rule'], f['message'])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    (out / 'findings.json').write_text(json.dumps({'units': units, 'findings': unique}, indent=1) + '\n')
    counts = collections.Counter((f['pass'], f['rule']) for f in unique)
    print(json.dumps({'units': len(units), 'failed_units': sum(u['returncode'] != 0 for u in units),
                      'findings': len(unique), 'by_rule': {'%s %s' % k: v for k, v in counts.most_common()}}, indent=1))


if __name__ == '__main__':
    main()
