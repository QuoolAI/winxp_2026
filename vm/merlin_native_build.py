#!/usr/bin/env python3
"""Build MerlinAI natively, end to end, in a disposable NIC-free clone of the
frozen NT build VM, then collect the binaries read-only.

Steps (each recorded in <run>/native-build.json):
  1. vm/native_build_lab.py: overlay of the frozen build image + the media ISO;
  2. wait for the desktop, then run D:\\build.cmd C:\\xpout\\<name> (xp_lab run);
  3. wait for XP25_MERLIN_BUILD_EXIT=<n> on COM1 (n != 0 is a failed build);
  4. guest shutdown (shutdown.exe in the build VM) and finish (disk frozen);
  5. extract the five binaries, their PDBs, the logs and every compiled source
     from the frozen disk; the sources must match the media manifest; every
     import is verified against the target guest's own system DLLs.
A zero exit code alone is not accepted: native.log must not contain
"nmake.exe failed" and all five binaries must exist.

usage: merlin_native_build.py --media <prepare_merlin output> --name <fresh> --base <frozen build disk>
                              [--guest-modules <...>/WINDOWS/system32] [--toolchain <mingw bin>]
                              [--artifacts <dir for runs>] [--timeout 2400]"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
OUTPUTS = {'MerlinClient.dll': 'client', 'MerlinCrash.exe': 'crash', 'MerlinAI.exe': 'app', 'MerlinAI.cpl': 'cpl',
           'MerlinSvc.exe': 'svc', 'MerlinTest.exe': 'testapp'}


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 22), b''):
            h.update(block)
    return h.hexdigest()


def run(cmd, **kw):
    return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--media', type=Path, required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--guest-modules', type=Path, default=ROOT / '.work/merlin-20261121/guest-modules-82/WINDOWS/system32')
    parser.add_argument('--toolchain', type=Path, default=ROOT / '.work/toolchains/mingw-binutils/usr/bin')
    parser.add_argument('--timeout', type=int, default=2400)
    args = parser.parse_args()
    media = args.media.resolve()
    iso = media / 'native-merlin.iso'
    manifest = json.loads((media / 'manifest.json').read_text())
    if sha(iso) != manifest['iso_sha256']:
        raise SystemExit('media ISO does not match its manifest')
    artifacts = ROOT / '.work/boot-debug-20261022'
    artifacts.mkdir(parents=True, exist_ok=True)
    run_dir = artifacts / args.name
    record = {'name': args.name, 'media': str(media), 'iso_sha256': manifest['iso_sha256'], 'base': str(args.base.resolve()),
              'steps': []}

    def step(name, **data):
        record['steps'].append({'step': name, 'time': time.time(), **data})
        if run_dir.exists():
            (run_dir / 'native-build.json').write_text(json.dumps(record, indent=2) + '\n')

    launch = run([sys.executable, ROOT / 'vm/native_build_lab.py', '--name', args.name, '--base', args.base, '--media', iso])
    step('launch', returncode=launch.returncode, stdout=launch.stdout[-2000:], stderr=launch.stderr[-2000:])
    if launch.returncode:
        raise SystemExit('build VM did not start: ' + launch.stderr)
    serial = run_dir / 'serial.log'
    # The build VM logs on automatically; give Explorer time before typing into Run.
    time.sleep(75)
    deadline = time.time() + args.timeout
    started = False
    for attempt in range(3):
        # A modal dialog (e.g. XP's Found New Hardware wizard) can hold the focus when the Run dialog opens
        # late under host load: dismiss it first and give the Run dialog time to settle.
        for _ in range(2):
            run([sys.executable, ROOT / 'vm/xp_lab.py', run_dir, 'key', 'esc'])
            time.sleep(1)
        r = run([sys.executable, ROOT / 'vm/xp_lab.py', run_dir, 'run', 'cmd /c D:\\build.cmd C:\\xpout\\' + args.name,
                 '--settle-seconds', '3'])
        step('run_build', attempt=attempt, returncode=r.returncode, stderr=r.stderr[-1000:])
        for _ in range(90):
            if serial.exists() and b'XP25_MERLIN_BUILD_STARTED' in serial.read_bytes():
                started = True
                break
            time.sleep(2)
        if started:
            break
    if not started:
        step('build_not_started')
        raise SystemExit('the build command did not start (see serial.log, screenshots)')
    exit_code = None
    while time.time() < deadline:
        text = serial.read_bytes().decode('latin-1')
        if 'XP25_MERLIN_BUILD_EXIT=' in text:
            exit_code = text.split('XP25_MERLIN_BUILD_EXIT=')[-1].split()[0]
            break
        time.sleep(5)
    step('build_exit', exit_code=exit_code)
    if exit_code is None:
        run([sys.executable, ROOT / 'vm/xp_lab.py', run_dir, 'screen', 'timeout'])
        raise SystemExit('build did not finish in time')
    time.sleep(5)
    r = run([sys.executable, ROOT / 'vm/xp_lab.py', run_dir, 'shutdown'])
    step('shutdown', returncode=r.returncode, stdout=r.stdout[-500:], stderr=r.stderr[-1000:])
    r = run([sys.executable, ROOT / 'vm/xp_lab.py', run_dir, 'finish'])
    step('finish', returncode=r.returncode, stderr=r.stderr[-1000:])
    if r.returncode:
        raise SystemExit('the build VM did not shut down normally')
    # Collect read-only from the frozen disk.
    collect = run_dir / 'collect'
    guest = []
    for name, folder in OUTPUTS.items():
        stem = name.rsplit('.', 1)[0]
        guest += ['/nt/xp25/merlin/merlin/%s/obj/i386/%s' % (folder, name), '/nt/xp25/merlin/merlin/%s/obj/i386/%s.pdb' % (folder, stem),
                  '/nt/xp25/merlin/merlin/%s/obj/i386/%s.map' % (folder, stem)]
    sources = [f for f in manifest['files'] if f.startswith('merlin/') and f.endswith(('.c', '.h', 'sources', '.rc', '.def'))]
    guest += ['/nt/xp25/' + f for f in sources]
    guest += ['/xpout/%s/%s' % (args.name, f) for f in ('native.log', 'build.log', 'build.err', 'build.wrn')]
    run([sys.executable, ROOT / 'vm/read_guest.py', run_dir / 'disk.qcow2', collect / 'extracted'] + guest)
    records = {r['guest_path']: r for r in json.loads((collect / 'extracted/files.json').read_text())['files']}
    mismatched = [f for f in sources if records.get('/nt/xp25/' + f, {}).get('sha256') != manifest['files'][f]]
    native_log = collect / ('extracted/xpout/%s/native.log' % args.name)
    log_text = native_log.read_text(errors='replace') if native_log.exists() else ''
    sys.path.insert(0, str(ROOT / 'build'))
    import ai_build
    ai_build.GUEST_MODULES = args.guest_modules.resolve()
    build = collect / 'build'
    build.mkdir(parents=True)
    result = {'status': 'failed', 'exit_code': exit_code, 'media_iso_sha256': manifest['iso_sha256'],
              'source_commit': manifest.get('source_commit'), 'sources_checked': len(sources), 'sources_mismatched': mismatched,
              'nmake_failed': 'nmake.exe failed' in log_text, 'binaries': {}, 'problems': []}
    objdump = str(args.toolchain.resolve() / 'i686-w64-mingw32-objdump')
    local = {'merlinclient.dll': set(l.strip() for l in (media / 'media/merlin/merlin/client/MerlinClient.def').read_text().splitlines()[2:] if l.strip())}
    for name, folder in OUTPUTS.items():
        src = collect / ('extracted/nt/xp25/merlin/merlin/%s/obj/i386/%s' % (folder, name))
        if not src.exists():
            result['problems'].append('missing ' + name)
            continue
        shutil.copy2(src, build / name)
        # Named after the full binary name: MerlinAI.exe and MerlinAI.cpl both link MerlinAI.map/.pdb.
        for suffix in ('.pdb', '.map'):
            symbols = src.with_name(name.rsplit('.', 1)[0] + suffix)
            if symbols.exists():
                shutil.copy2(symbols, build / (name + suffix))
        try:
            imports = ai_build.verify(objdump, build / name, local, exact_51=False)
        except ValueError as error:
            result['problems'].append(str(error))
            imports = None
        result['binaries'][name] = {'sha256': sha(src), 'bytes': src.stat().st_size, 'imports': imports}
    if exit_code != '0':
        result['problems'].append('build exit ' + str(exit_code))
    if result['nmake_failed']:
        result['problems'].append('nmake.exe failed in native.log')
    if mismatched:
        result['problems'].append('compiled sources differ from the media')
    # build/package_image.py reads collection records by their 'files' list.
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
