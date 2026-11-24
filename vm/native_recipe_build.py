#!/usr/bin/env python3
"""Build one MerlinAI Builder recipe natively, end to end, in a disposable NIC-free clone of the frozen NT
build VM, then collect the results read-only. The media come from build/prepare_recipe.py; its manifest
names the COM1 marker, the outputs and the sources to check.

Steps (each recorded in <run>/native-build.json):
  1. vm/native_build_lab.py: overlay of the frozen build image + the media ISO;
  2. wait for the desktop, then run D:\\build.cmd C:\\xpout\\<name> (xp_lab run);
  3. wait for <marker>_EXIT=<n> on COM1 (n != 0 is a failed build);
  4. guest shutdown and finish (disk frozen);
  5. extract the outputs, symbols and logs read-only and check them:
     xp25 recipes: every compiled source matches the media, native.log has no "nmake.exe failed", every
       output exists and every import resolves against another output of the same build or the guest's
       own DLL in --guest-modules (a DLL that copy lacks is recorded as unchecked; the builder checks
       every import against the baseline image itself);
     nt recipes: both the control build (XP25's effective sources) and the candidate build (the job's) left
       every output and no "nmake.exe failed" in any build log.
A zero exit code alone is never accepted.

usage: native_recipe_build.py --media <prepare_recipe output> --name <fresh> --base <frozen build disk>
                              [--guest-modules <...>/WINDOWS/system32] [--toolchain <mingw bin>] [--timeout 3600]"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'components/merlin/builder'))
from merlin_builder import pe  # noqa: E402


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 22), b''):
            h.update(block)
    return h.hexdigest()


def run(cmd, **kw):
    return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)


def drive(name, base, iso, marker, timeout, step):
    """Run the media's build.cmd in a fresh build VM and freeze it; returns (run directory, exit code text)."""
    run_dir = ROOT / '.work/boot-debug-20261022' / name
    launch = run([sys.executable, ROOT / 'vm/native_build_lab.py', '--name', name, '--base', base, '--media', iso])
    step('launch', returncode=launch.returncode, stdout=launch.stdout[-2000:], stderr=launch.stderr[-2000:])
    if launch.returncode:
        raise SystemExit('build VM did not start: ' + launch.stderr)
    serial = run_dir / 'serial.log'
    time.sleep(75)                                      # the build VM logs on automatically; let Explorer start
    started = False
    for attempt in range(3):
        # A modal dialog (e.g. the Found New Hardware wizard) can hold the focus when the Run dialog opens late.
        for _ in range(2):
            run([sys.executable, ROOT / 'vm/xp_lab.py', run_dir, 'key', 'esc'])
            time.sleep(1)
        r = run([sys.executable, ROOT / 'vm/xp_lab.py', run_dir, 'run', 'cmd /c D:\\build.cmd C:\\xpout\\' + name, '--settle-seconds', '3'])
        step('run_build', attempt=attempt, returncode=r.returncode, stderr=r.stderr[-1000:])
        for _ in range(90):
            if serial.exists() and (marker + '_STARTED').encode() in serial.read_bytes():
                started = True
                break
            time.sleep(2)
        if started:
            break
    if not started:
        step('build_not_started')
        raise SystemExit('the build command did not start (see serial.log, screenshots)')
    exit_code, deadline = None, time.time() + timeout
    while time.time() < deadline:
        text = serial.read_bytes().decode('latin-1')
        if marker + '_EXIT=' in text:
            exit_code = text.split(marker + '_EXIT=')[-1].split()[0]
            break
        time.sleep(5)
    step('build_exit', exit_code=exit_code)
    if exit_code is None:
        run([sys.executable, ROOT / 'vm/xp_lab.py', run_dir, 'screen', 'timeout'])
        raise SystemExit('build did not finish in time')
    time.sleep(5)
    # The guest can take minutes to power off when the host is busy.
    r = run([sys.executable, ROOT / 'vm/xp_lab.py', run_dir, 'shutdown', '--shutdown-timeout', '600'])
    step('shutdown', returncode=r.returncode, stdout=r.stdout[-500:], stderr=r.stderr[-1000:])
    r = run([sys.executable, ROOT / 'vm/xp_lab.py', run_dir, 'finish'])
    step('finish', returncode=r.returncode, stderr=r.stderr[-1000:])
    if r.returncode:
        raise SystemExit('the build VM did not shut down normally')
    return run_dir, exit_code


def collect_xp25(manifest, media, name, collect, args, result):
    guest = []
    for o in manifest['outputs']:
        stem = o['guest'].rsplit('.', 1)[0]
        guest += [o['guest'], stem + '.pdb', stem + '.map']
    guest += list(manifest['compiled'].values())
    guest += ['/xpout/%s/%s' % (name, f) for f in ('native.log', 'build.log', 'build.err', 'build.wrn')]
    run([sys.executable, ROOT / 'vm/read_guest.py', collect.parent / 'disk.qcow2', collect / 'extracted'] + guest)
    records = {r['guest_path']: r for r in json.loads((collect / 'extracted/files.json').read_text())['files']}
    mismatched = [f for f, g in manifest['compiled'].items() if records.get(g, {}).get('sha256') != manifest['media_files'][f]]
    log = collect / ('extracted/xpout/%s/native.log' % name)
    result['nmake_failed'] = 'nmake.exe failed' in (log.read_text(errors='replace') if log.exists() else '')
    result['sources_checked'], result['sources_mismatched'] = len(manifest['compiled']), mismatched
    if mismatched:
        result['problems'].append('compiled sources differ from the media')
    if not log.exists():
        result['problems'].append('no native.log')
    build = collect / 'build'
    built = {}
    for o in manifest['outputs']:
        src = collect / ('extracted' + o['guest'])
        if not src.exists():
            result['problems'].append('missing ' + o['target'])
            continue
        shutil.copy2(src, build / o['target'])
        for suffix in ('.pdb', '.map'):
            symbols = src.with_name(src.name.rsplit('.', 1)[0] + suffix)
            if symbols.exists():
                shutil.copy2(symbols, build / (o['target'] + suffix))
        built[o['target']] = build / o['target']
    # Imports resolve against another output of the same build, else against the guest's own DLL. A DLL that the
    # guest-modules copy lacks is recorded as unchecked: the builder checks every import against the baseline
    # image itself before a candidate is assembled.
    local = {t.lower(): pe.PE(p.read_bytes()) for t, p in built.items() if t.lower().endswith('.dll')}
    exports = {}
    for target, path in built.items():
        missing, unchecked = [], []
        for dll, names in sorted(pe.PE(path.read_bytes()).imports().items()):
            if dll not in exports:
                source = local.get(dll)
                if source is None:
                    candidates = [p for p in args.guest_modules.iterdir() if p.name.lower() == dll]
                    source = pe.PE(candidates[0].read_bytes()) if candidates else None
                exports[dll] = (set(source.exports()) | source.export_ordinals()) if source else None
            if exports[dll] is None:
                unchecked.append(dll)
            else:
                missing += ['%s!%s' % (dll, n) for n in names if n not in exports[dll]]
        if missing:
            result['problems'].append('%s imports what its guest does not export: %s' % (target, ', '.join(missing)))
        result['binaries'][target] = {'sha256': sha(path), 'bytes': path.stat().st_size, 'imports_unresolved': missing,
                                      'imports_unchecked_dlls': unchecked}


def collect_nt(manifest, name, collect, result):
    guest = ['/xpout/%s/%s' % (name, f) for f in manifest['collect']]
    stages = len(manifest['dirs'])
    guest += ['/xpout/%s/%s-%d.log' % (name, stage, n) for stage in ('control', 'candidate') for n in range(1, stages + 1)]
    run([sys.executable, ROOT / 'vm/read_guest.py', collect.parent / 'disk.qcow2', collect / 'extracted'] + guest)
    for stage in ('control', 'candidate'):
        for n in range(1, stages + 1):
            log = collect / ('extracted/xpout/%s/%s-%d.log' % (name, stage, n))
            if not log.exists():
                result['problems'].append('no %s build log %d' % (stage, n))
            elif 'nmake.exe failed' in log.read_text(errors='replace'):
                result['nmake_failed'] = True
                result['problems'].append('nmake.exe failed in the %s build (%s)' % (stage, manifest['dirs'][n - 1]))
    for item in manifest['collect']:
        src = collect / ('extracted/xpout/%s/%s' % (name, item))
        if not src.exists():
            result['problems'].append('missing ' + item)
            continue
        target = collect / 'build' / item
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)
        if item.endswith(('.exe', '.dll', '.sys')):
            result['binaries'][item] = {'sha256': sha(src), 'bytes': src.stat().st_size}
    result['sources'] = manifest['files']


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--media', type=Path, required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--guest-modules', type=Path, default=ROOT / '.work/merlin-20261121/guest-modules-82/WINDOWS/system32')
    parser.add_argument('--toolchain', type=Path, default=ROOT / '.work/toolchains/mingw-binutils/usr/bin')
    parser.add_argument('--timeout', type=int, default=3600)
    args = parser.parse_args()
    media = args.media.resolve()
    manifest = json.loads((media / 'manifest.json').read_text())
    if manifest['kind'] == 'xp25' and not (args.guest_modules / 'user32.dll').is_file():
        raise SystemExit('--guest-modules must be the target guest system32 directory (imports are checked against it)')
    iso = media / manifest['iso']
    if sha(iso) != manifest['iso_sha256']:
        raise SystemExit('media ISO does not match its manifest')
    record = {'name': args.name, 'recipe': manifest['recipe'], 'media': str(media), 'iso_sha256': manifest['iso_sha256'],
              'base': str(args.base.resolve()), 'steps': []}
    run_dir = ROOT / '.work/boot-debug-20261022' / args.name

    def step(name, **data):
        record['steps'].append({'step': name, 'time': time.time(), **data})
        if run_dir.exists():
            (run_dir / 'native-build.json').write_text(json.dumps(record, indent=2) + '\n')

    run_dir, exit_code = drive(args.name, args.base, iso, manifest['marker'], args.timeout, step)
    collect = run_dir / 'collect'
    (collect / 'build').mkdir(parents=True)
    result = {'status': 'failed', 'recipe': manifest['recipe'], 'kind': manifest['kind'], 'exit_code': exit_code,
              'media_iso_sha256': manifest['iso_sha256'], 'source_commit': manifest.get('source_commit'),
              'nmake_failed': False, 'binaries': {}, 'problems': []}
    if manifest['kind'] == 'xp25':
        collect_xp25(manifest, media, args.name, collect, args, result)
    else:
        collect_nt(manifest, args.name, collect, result)
    if exit_code != '0':
        result['problems'].append('build exit ' + str(exit_code))
    if result['nmake_failed'] and 'nmake.exe failed in native.log' not in result['problems'] and manifest['kind'] == 'xp25':
        result['problems'].append('nmake.exe failed in native.log')
    result['files'] = [{'name': n, 'sha256': b['sha256']} for n, b in result['binaries'].items()]
    result['status'] = 'accepted' if not result['problems'] else 'failed'
    (collect / 'collect.json').write_text(json.dumps(result, indent=2) + '\n')
    step('collected', status=result['status'], problems=result['problems'])
    print(json.dumps({k: v for k, v in result.items() if k != 'binaries'}, indent=2))
    for name, b in result['binaries'].items():
        print(name, b['sha256'], b['bytes'])
    return 0 if result['status'] == 'accepted' else 2


if __name__ == '__main__':
    raise SystemExit(main())
